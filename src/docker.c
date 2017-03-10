/**
 * collectd - src/docker.c
 * Copyright (C) 2017  Google Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Dhrupad Bhardwaj <dhrupad at google.com>
 **/

#include "collectd.h"
#include "utils_avltree.h"

#include "common.h"
#include "plugin.h"

#include <curl/curl.h>
#include "yajl/yajl_tree.h"

// Default size of the response buffer when calling the Docker stats API
#define RESPONSE_BUFFER_SIZE 16400

// The default version of the Docker API engine and the default UNIX socket
// to which the API writes responses.
static const char *DEFAULT_SOCKET = "/var/run/docker.sock";
static const char *DEFAULT_VERSION = "1.23";

typedef struct {
  char *data;
  size_t size;
} curl_write_ctx_t;

//Block IO (Disk) Stats
static const char *BLKIO_TYPE_KEYS[] = {
  "major",
  "minor",
  "value",
};

// Disk metrics for a given device (sda/ or 8.0)
typedef struct {
  unsigned long read;
  unsigned long write;
  unsigned long sync;
  unsigned long async;
  unsigned long total;
} blkio_device_stats_t;

typedef struct {
  c_avl_tree_t *io_bytes;
} blkio_stats_t;

static const char *BLKIO_KEYS[] = {
  "io_service_bytes_recursive",
};

static const char *BLKIO_PATH[] = { "blkio_stats", (const char *) 0 };

//CPU Stats
typedef struct {
  unsigned long system_cpu_usage;
  unsigned long num_cpus;
  unsigned long *percpu_usage;
  unsigned long *percpu_idle;
  double *percpu_percent_used;
  double *percpu_percent_idle;
} cpu_stats_t;

// Structure which stores historical CPU metrics from interval t-1
// needed in order to calculate deltas from cumulative values
typedef struct {
  cdtime_t t;
  unsigned long old_system_usage;
  unsigned long *old_percpu_usage;
  unsigned long num_cpus;
} cpu_state_t;

c_avl_tree_t *cpu_hist_values;

static const char *CPU_KEYS[] = {
  "system_cpu_usage",
};

static const char *CPU_PATH[] = { "cpu_stats", (const char *) 0 };

//Memory Stats
typedef struct {
  unsigned long usage;
  unsigned long limit;
  unsigned long free;
  float used_percentage;
  float free_percentage;
} memory_stats_t;

static const char *MEMORY_RESPONSE_KEYS[] = {
  "usage",
  "limit",
};

static const char *MEMORY_METRIC_TYPES[] = {
  "used",
  "available",
};

static const char *MEMORY_PATH[] = { "memory_stats", (const char *) 0 };

// Connection metrics for a given interface (e.g eth0)
typedef struct {
  char *name;
  unsigned long rx_bytes;
  unsigned long rx_packets;
  unsigned long rx_errors;
  unsigned long tx_bytes;
  unsigned long tx_packets;
  unsigned long tx_errors;
} interface_stats_t;

static const char *INTERFACE_KEYS[] = {
  "bytes",
  "packets",
  "errors",
};

static const char *NETWORK_PATH[] = { "networks", (const char *) 0 };

typedef struct {
  size_t count;
  interface_stats_t **interfaces;
} network_stats_t;

typedef struct {
  blkio_stats_t *blkio_stats;
  cpu_stats_t *cpu_stats;
  memory_stats_t *memory_stats;
  network_stats_t *network_stats;
  char *name;
} container_stats_t;

typedef struct {
  char *id;
  container_stats_t *stats;
} container_resource_t;

static const char *DOCKER_VERSION = NULL;
static const char *DOCKER_SOCKET = NULL;

static const char *config_version = NULL;
static const char *config_socket = NULL;

static const char *config_keys[] = {
  "Socket",
  "Version"
};

static int config_keys_num = STATIC_ARRAY_SIZE(config_keys);

//==============================================================================
//==============================================================================
//==============================================================================
// Misc utility functions.
//==============================================================================
//==============================================================================
//==============================================================================

static void free_list(void ***p, int size) {
  void **ptr = *(p);
  for (int i = 0; i < size; i++) {
    if (ptr[i] != NULL) {
      sfree(ptr[i]);
      ptr[i] = NULL;
    }
  }
  sfree(ptr);
  ptr = NULL;
}

// Takes a comma separated list and creates an array of Strings terminated
// by a NULL string. Used to create paths required to traverse the YAJL tree.
static const char **tokenize_path(const char *path, int *len) {
  int count = 1;
  for (int i = 0; i < strlen(path); i++) {
    if (path[i] == ',') {
      count++;
    }
  }
  char *copy_str = sstrdup(path);
  char *ptr = copy_str;
  const char **tokens = (const char **) calloc(count + 1, sizeof(char *));
  if (tokens == NULL) {
    ERROR("docker: tokenize_path: malloc failed!");
  }
  char *rest = (char *) path;
  const char **tok_ptr = tokens;
  ptr = strtok_r(copy_str, ",", &rest);
  while (ptr != NULL) {
    *tokens = ptr;
    tokens++;
    ptr = strtok_r(NULL, ",", &rest);
  }
  *tokens = (const char *) 0;
  *(len) = count;
  return tok_ptr;
}

static void free_blkio_device_tree(c_avl_tree_t *tree) {
  void *key;
  void *value;
  while (1) {
    if(c_avl_pick(tree, (void **) &key, (void **) &value) == 0) {
      sfree(key);
      sfree(value);
    } else goto leave;
  }
 leave:
  c_avl_destroy(tree);
}

static void free_blkio(blkio_stats_t * stats) {
  c_avl_tree_t *ptrs[] = {
    stats->io_bytes,
  };
  for (int i = 0; i < STATIC_ARRAY_SIZE(ptrs); i++) {
    if (ptrs[i] != NULL) {
      free_blkio_device_tree(ptrs[i]);
    }
  }
  sfree(stats);
}

static void free_cpu(cpu_stats_t * stats) {
  sfree(stats->percpu_usage);
  sfree(stats->percpu_idle);
  sfree(stats->percpu_percent_used);
  sfree(stats->percpu_percent_idle);
  sfree(stats);
}

static void free_network_stats(network_stats_t * stats) {
  if (stats == NULL) {
    return;
  }
  for (int i = 0; i < stats->count; i++) {
    if (stats->interfaces[i] != NULL) {
      sfree(stats->interfaces[i]->name);
      sfree(stats->interfaces);
    }
  }
  sfree(stats);
}

static void free_stats(container_stats_t * stats) {
  if (stats->blkio_stats != NULL) {
    free_blkio(stats->blkio_stats);
  }
  if (stats->cpu_stats != NULL) {
    free_cpu(stats->cpu_stats);
  }
  if (stats->memory_stats != NULL) {
    sfree(stats->memory_stats);
  }
  if (stats->network_stats != NULL) {
    free_network_stats(stats->network_stats);
  }
  if (stats->name != NULL) {
    sfree(stats->name);
  }
 sfree(stats);
}

// Taken from src/write_gcm.c
static size_t plugin_curl_write_callback(char *ptr, size_t size, size_t nmemb,
    void *userdata) {
  curl_write_ctx_t *ctx = userdata;
  if (ctx->size == 0) {
    return 0;
  }
  size_t requested_bytes = size * nmemb;
  size_t actual_bytes = requested_bytes;
  if (actual_bytes >= ctx->size) {
    actual_bytes = ctx->size - 1;
  }
  memcpy(ctx->data, ptr, actual_bytes);
  ctx->data += actual_bytes;
  ctx->size -= actual_bytes;

  // We lie about the number of bytes successfully transferred in order to
  // prevent curl from returning an error to our caller. Our caller is keeping
  // track of buffer consumption so it will independently know if the buffer
  // filled up; the only errors it wants to hear about from curl are the more
  // catastrophic ones.
  return requested_bytes;
}

// Using implementation with modifications from src/write_gcm.c
static int curl_get_json(char *response_buffer, size_t response_buffer_size,
    const char *url, const char *socket) {
  CURL *curl = curl_easy_init();
  if (curl == NULL) {
    ERROR("docker: curl_easy_init failed");
    return -1;
  }
  const char *useragent = "stackdriver-docker-plugin";
  curl_write_ctx_t write_ctx = {
    .data = response_buffer,
    .size = response_buffer_size
  };

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent);
  int status = curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, socket);
  if (status != CURLE_OK) {
    ERROR("docker: curl_easy_setopt() failed: %s\n",
	  curl_easy_strerror(status));
  }
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &plugin_curl_write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);
  // http://stackoverflow.com/questions/9191668/error-longjmp-causes-uninitialized-stack-frame
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);	// 5 seconds.

  int result = -1;		// Pessimistically assume error.

  int curl_result = curl_easy_perform(curl);
  if (curl_result != CURLE_OK) {
    ERROR("docker: curl_easy_perform() failed: %s",
	  curl_easy_strerror(curl_result));
    goto leave;
  }

  long response_code;
  curl_result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
  write_ctx.data[0] = 0;
  if (response_code >= 400) {
    ERROR("docker: Unsuccessful HTTP request %ld: %s",
	  response_code, response_buffer);
    result = -2;
    goto leave;
  }

  if (write_ctx.size < 2) {
    ERROR("docker: curl_get_json: The receive buffer overflowed.");
    DEBUG("docker: curl_get_json: Received data is: %s", response_buffer);
    goto leave;
  }

  result = 0;			// Success!

leave:
  curl_easy_cleanup(curl);
  return result;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Functionality to compute derived statistics.
//==============================================================================
//==============================================================================
//==============================================================================

// Computes percentages for CPU metrics in different states.
static void compute_cpu_stats(cpu_stats_t *stats, const char *container_id) {
  cdtime_t now = cdtime();
  cpu_state_t *old_stats = NULL;
  if (c_avl_get(cpu_hist_values, (void *) container_id,
                    (void **) &old_stats) == 0) {
    assert(stats->num_cpus == old_stats->num_cpus);
    assert(now >= old_stats->t);
    for (int i = 0; i < stats->num_cpus; i++) {
      // In case the counters reset
      if ((stats->percpu_usage[i] < old_stats->old_percpu_usage[i]) ||
              (stats->system_cpu_usage < old_stats->old_system_usage)) {
        goto counter_reset;
      }
      unsigned long delta_cpu = stats->percpu_usage[i] -
          old_stats->old_percpu_usage[i];
      unsigned long delta_system = stats->system_cpu_usage -
          old_stats->old_system_usage;
      if (delta_system < delta_cpu) {
        ERROR("docker.c: System seconds less than Core seconds."
              " System Seconds: %lu, CPU Seconds: %lu", delta_system, delta_cpu);
      }
      unsigned long used_percent =
          delta_system > 0 ? 100.0*((delta_cpu*1.00)/(1.00*delta_system)) : 0.00;
      stats->percpu_percent_used[i] = (used_percent)%100;
      stats->percpu_percent_idle[i] = 100.00 - ((used_percent)%100);
    counter_reset:
      stats->percpu_idle[i] = stats->system_cpu_usage - stats->percpu_usage[i];
      old_stats->old_percpu_usage[i] = stats->percpu_usage[i];
      old_stats->old_system_usage = stats->system_cpu_usage;
    }
  } else {
    cpu_state_t *old_stats = (cpu_state_t *) calloc(1, sizeof(cpu_state_t));
    old_stats->num_cpus = stats->num_cpus;
    old_stats->old_system_usage = stats->system_cpu_usage;
    old_stats->old_percpu_usage =
        (unsigned long *) calloc(stats->num_cpus, sizeof(unsigned long));
    for (int i = 0; i < stats->num_cpus; i++) {
      old_stats->old_percpu_usage[i] = stats->percpu_usage[i];
      stats->percpu_percent_used[i] = stats->system_cpu_usage > 0 ?
          (100.00*stats->percpu_usage[i])/(1.00*stats->system_cpu_usage) : 0.00;
      stats->percpu_percent_idle[i] = 100.00 - stats->percpu_percent_used[i];
      stats->percpu_idle[i] = stats->system_cpu_usage - stats->percpu_usage[i];
    }
    if (c_avl_insert(cpu_hist_values, (void *) container_id,
           (void *) old_stats) < 0) {
      ERROR("docker: c_avl_insert failed!");
    }
  }
}

// Computes percentages for Memory metrics in different states.
static void compute_memory_stats(memory_stats_t *stats) {
  stats->free = stats->limit - stats->usage;
  stats->used_percentage = (stats->usage * 100.00)/(stats->limit);
  stats->free_percentage = 100.00 - stats->used_percentage;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Functionality to parse the Docker Stats JSON response and retrieve stats.
//==============================================================================
//==============================================================================
//==============================================================================

// Retrieves the list of 64 character container IDs from the containers/json
// endpoint.
static int extract_container_ids_from_response(char ***container_list,
    char *response_buffer) {
  yajl_val node;
  char errbuf[1024];
  int num_containers = -1;
  char **list;
  node = yajl_tree_parse(response_buffer, errbuf, sizeof(errbuf));
  if (node == NULL) {
    if (strlen(errbuf)) {
      ERROR("docker: parse_error: %s.\n", errbuf);
    } else {
      ERROR("docker: extract_container_ids_from_response: parse_error.\n");
    }
    goto error;
  }
  if (node->u.array.len == 0) {
    return 0;
  }

  const char *id_path[] = { "Id", (const char *) 0 };
  if (YAJL_IS_ARRAY(node)) {
    list = (char **) calloc(node->u.array.len, sizeof(char *));
    if (list == NULL) {
      ERROR("docker: extract_container_ids_from_response: malloc failed!");
    }
    num_containers = node->u.array.len;
    for (int i = 0; i < num_containers; i++) {
      yajl_val elem = node->u.array.values[i];
      yajl_val id_node = yajl_tree_get(elem, id_path, yajl_t_string);
      if (!YAJL_IS_OBJECT(id_node)) {
	list[i] = sstrdup(YAJL_GET_STRING(id_node));
      } else {
	ERROR("docker: Container ID could not be extracted.\n");
      }
    }
    *(container_list) = list;
  }
error:
  yajl_tree_free(node);
  return num_containers;
}

static int get_container_list(char ***container_list, const char *socket,
    const char *version) {
  char *response_buffer = (char *) calloc(RESPONSE_BUFFER_SIZE, sizeof(char));
  char *url = (char *) calloc(28, sizeof(char));
  if (response_buffer == NULL || url == NULL) {
    ERROR("docker: get_container_list: malloc failed!");
  }
  ssnprintf(url, 28, "http:/v%s/containers/json", version);
  curl_get_json(response_buffer, RESPONSE_BUFFER_SIZE, url, socket);
  int count =
      extract_container_ids_from_response(container_list, response_buffer);
  sfree(response_buffer);
  sfree(url);
  return count;
}

// Extracts a String from the YAJL node and sets it to the result_ptr.
static void extract_string(yajl_val node, const char *key, char **result_ptr) {
  char *result = 0;
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_string);
  if (YAJL_IS_STRING(val_node)) {
    result = sstrdup(YAJL_GET_STRING(val_node));
  } else {
    WARNING("docker: %s not parsed.", key);
  }
  free_list((void ***) &path, tokens-1);
  *(result_ptr) = result;
}

// Extracts an array of unsigned long values from the YAJL node.
// Retuns the number of array elements. -1 in case of an error.
static int extract_arr_value(yajl_val node, const char *key,
    unsigned long **result_ptr) {
  int tokens;
  int len;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_array);
  if (YAJL_IS_ARRAY(val_node)) {
    unsigned long *ptrs = (unsigned long *)
        calloc(val_node->u.array.len, sizeof(unsigned long));
    if (ptrs == NULL) {
      ERROR("docker_plugin: extract_arr_value malloc failed.\n");
      sfree(ptrs);
      free_list((void ***) &path, tokens-1);
      return -1;
    }
    for (int i = 0; i < val_node->u.array.len; i++) {
      ptrs[i] = YAJL_GET_INTEGER(val_node->u.array.values[i]);
    }
    *(result_ptr) = ptrs;
    len = val_node->u.array.len;
  } else {
    WARNING("docker_plugin: %s not parsed.", key);
    len = -1;
  }

  // We don't want to free the tokens[len-1]th element as it is a NULL string.
  free_list((void ***) &path, tokens-1);
  return len;
}

// Extracts a single unsigned long value from the YAJL node.
static void extract_value(yajl_val node, const char *key,
    unsigned long *result_ptr) {
  unsigned long result = 0;
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_any);
  if (YAJL_IS_ARRAY(val_node)) {
    if (val_node->u.array.len > 0)
      result = YAJL_GET_INTEGER(val_node->u.array.values[0]);
  } else if (YAJL_IS_NUMBER(val_node)) {
    result = YAJL_GET_INTEGER(val_node);
  } else {
    WARNING("docker: %s not parsed.", key);
  }
  free_list((void ***) &path, tokens-1);
  *(result_ptr) = result;
}

// Takes a parsed BlockIO stats and creates a stat structure for that device
// or updates the stats for an existing device.
static int insert_blkio_stat_in_tree(c_avl_tree_t *tree, char *op,
    unsigned long major, unsigned long minor, unsigned long value) {
  int result = -1;
  char *key = (char *) calloc(4, sizeof(char));
  ssnprintf(key, 4, "%lu.%lu", major, minor);
  blkio_device_stats_t *stats = NULL;
 insert:
  if (c_avl_get(tree, (const void *) key, (void *) (&stats)) == 0) {
    if (strcmp(op, "Read") == 0) {
      stats->read = value;
    }
    if (strcmp(op, "Write") == 0) {
      stats->write = value;
    }
    if (strcmp(op, "Sync") == 0) {
      stats->sync = value;
    }
    if (strcmp(op, "Async") == 0) {
      stats->async = value;
    }
    if (strcmp(op, "Total") == 0) {
      stats->total = value;
    }
  } else {
    stats = (blkio_device_stats_t *) calloc (1, sizeof(blkio_device_stats_t));
    if (c_avl_insert(tree, (void *) key, (void *) stats) < 0) {
      ERROR ("docker: c_avl_insert failed due to error.");
      sfree(stats);
      return result;
    }
    goto insert;
  }
  result = 0;
  return result;
}

// Extracts BlockIO (Disk) stats of a given type from the STATS API response.
static int extract_blkio_values(yajl_val node, c_avl_tree_t *tree) {
  int result = -1;
  unsigned long major, minor, value;
  unsigned long *result_ptr[] = {
    &(major),
    &(minor),
    &(value),
  };

  assert(STATIC_ARRAY_SIZE(BLKIO_TYPE_KEYS) == STATIC_ARRAY_SIZE(result_ptr));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_TYPE_KEYS); i++) {
    extract_value(node, BLKIO_TYPE_KEYS[i], result_ptr[i]);
  }
  static const char *op_path[] = { "op", (const char *) 0 };
  yajl_val op_node = yajl_tree_get(node, op_path, yajl_t_string);
  if (YAJL_IS_STRING(op_node)) {
    char *op = YAJL_GET_STRING(op_node);
    result = insert_blkio_stat_in_tree(tree, op, major, minor, value);
  }
  return result;
}

// Extracts all BlockIO (Disk) stats for all devices and populates the
// device to stats tree.
static void extract_blkio_struct(yajl_val node, const char *key,
                                 c_avl_tree_t **result_ptr) {
  c_avl_tree_t *device_tree = c_avl_create((
      int(*)(const void *, const void *))&strcmp);
  if (device_tree == NULL) {
    ERROR("docker: extract_blkio_struct: c_avl_create failed!");
    goto leave;
  }
  int tokens;
  const char **path = tokenize_path(key, &tokens);
  yajl_val val_node = yajl_tree_get(node, path, yajl_t_any);
  if (YAJL_IS_ARRAY(val_node) && val_node->u.array.len > 0) {
    for (int i = 0; i < val_node->u.array.len; i++) {
      if(extract_blkio_values(val_node->u.array.values[i], device_tree) == -1) {
        goto leave;
      }
    }
  } else goto leave;
  free_list((void ***) &path, tokens-1);
  *(result_ptr) = device_tree;
  return;

 leave:
  c_avl_destroy(device_tree);
  device_tree = NULL;
  *(result_ptr) = device_tree;
}

static void get_blkio_stats(yajl_val node, container_stats_t * stats) {
  stats->blkio_stats = (blkio_stats_t *) calloc(1, sizeof(blkio_stats_t));
  if (stats->blkio_stats == NULL) {
    ERROR("docker: get_block_io_stats: malloc failed!");
  }
  yajl_val blkio_node = yajl_tree_get(node, BLKIO_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(blkio_node)) {
    ERROR("docker: JSON Error. \n");
    sfree(stats->blkio_stats);
    return;
  }

  c_avl_tree_t **result_ptrs[] = {
    &(stats->blkio_stats->io_bytes),
  };

  assert(STATIC_ARRAY_SIZE(BLKIO_KEYS) == STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_KEYS); i++) {
    extract_blkio_struct(blkio_node, BLKIO_KEYS[i], result_ptrs[i]);
  }
}

// Retrieves CPU statistics from the STATS API response
static void get_cpu_stats(yajl_val node, container_stats_t * stats,
    const char *container_id) {
  stats->cpu_stats = (cpu_stats_t *) calloc(1, sizeof(cpu_stats_t));
  if (stats->cpu_stats == NULL) {
    ERROR("docker: get_cpu_stats: malloc failed!");
  }
  yajl_val cpu_node = yajl_tree_get(node, CPU_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(cpu_node)) {
    ERROR("docker: JSON Error. \n");
    sfree(stats->cpu_stats);
    return;
  }

  unsigned long *result_ptrs[] = {
    &(stats->cpu_stats->system_cpu_usage),
  };

  assert(STATIC_ARRAY_SIZE(CPU_KEYS) == STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(CPU_KEYS); i++) {
    extract_value(cpu_node, CPU_KEYS[i], result_ptrs[i]);
  }
  int len = extract_arr_value(cpu_node, "cpu_usage,percpu_usage",
      &(stats->cpu_stats->percpu_usage));
  stats->cpu_stats->num_cpus = (unsigned long) len;
  stats->cpu_stats->percpu_idle =
      (unsigned long *) calloc(len, sizeof(unsigned long));
  stats->cpu_stats->percpu_percent_used = (double *) calloc(len, sizeof(double));
  stats->cpu_stats->percpu_percent_idle = (double *) calloc(len, sizeof(double));
  compute_cpu_stats(stats->cpu_stats, container_id);
}

// Retrieves Memory statistics from the STATS API response
static void get_memory_stats(yajl_val node, container_stats_t * stats) {
  stats->memory_stats = (memory_stats_t *) calloc(1, sizeof(memory_stats_t));
  if (stats->memory_stats == NULL) {
    ERROR("docker: get_memory_stats: malloc failed!");
  }
  yajl_val memory_node = yajl_tree_get(node, MEMORY_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(memory_node)) {
    ERROR("docker: JSON Error. \n");
    sfree(stats->memory_stats);
    return;
  }

  unsigned long *result_ptrs[] = {
    &(stats->memory_stats->usage),
    &(stats->memory_stats->limit),
  };

  assert(STATIC_ARRAY_SIZE(MEMORY_RESPONSE_KEYS) ==
         STATIC_ARRAY_SIZE(result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(MEMORY_RESPONSE_KEYS); i++) {
    extract_value(memory_node, MEMORY_RESPONSE_KEYS[i], result_ptrs[i]);
  }
  compute_memory_stats(stats->memory_stats);
}

// Extracts stats for a given interface.
static void get_interface_stats(yajl_val interface_node,
    interface_stats_t * stats) {
  //Network Stats
  unsigned long *rx_result_ptrs[] = {
    &(stats->rx_bytes),
    &(stats->rx_packets),
    &(stats->rx_errors),
  };

  unsigned long *tx_result_ptrs[] = {
    &(stats->tx_bytes),
    &(stats->tx_packets),
    &(stats->tx_errors),
  };

  assert(STATIC_ARRAY_SIZE(INTERFACE_KEYS) == STATIC_ARRAY_SIZE(rx_result_ptrs));
  assert(STATIC_ARRAY_SIZE(INTERFACE_KEYS) == STATIC_ARRAY_SIZE(tx_result_ptrs));
  for (int i = 0; i < STATIC_ARRAY_SIZE(INTERFACE_KEYS); i++) {
    int len = strlen(INTERFACE_KEYS[i]) + 4; //tx_{bytes}\0
    char *tx_key = (char *) calloc(len, sizeof(char));
    char *rx_key = (char *) calloc(len, sizeof(char));
    if (tx_key == NULL || rx_key == NULL) {
      ERROR("docker: get_metrics_for_container: malloc failed.\n");
    }
    ssnprintf(tx_key, len, "tx_%s", INTERFACE_KEYS[i]);
    ssnprintf(rx_key, len, "rx_%s", INTERFACE_KEYS[i]);
    extract_value(interface_node, tx_key, tx_result_ptrs[i]);
    extract_value(interface_node, rx_key, rx_result_ptrs[i]);
    sfree(tx_key);
    sfree(rx_key);
  }
}

// Retrieves Network statistics for each networking interface from the STATS API
// response.
static void get_network_stats(yajl_val node, container_stats_t * stats) {
  stats->network_stats = (network_stats_t *) calloc(1, sizeof(network_stats_t));
  if (stats->network_stats == NULL) {
    ERROR("docker: get_network_stats: malloc failed!");
  }

  yajl_val network_node = yajl_tree_get(node, NETWORK_PATH, yajl_t_object);
  if (!YAJL_IS_OBJECT(network_node)) {
    ERROR("docker: JSON Error. \n");
    sfree(stats->network_stats);
    return;
  }
  unsigned int num_interfaces = STATIC_ARRAY_SIZE(network_node->u.object.keys);
  stats->network_stats->interfaces = (interface_stats_t **)
      calloc(num_interfaces, sizeof(interface_stats_t *));
  if (stats->network_stats->interfaces == NULL) {
    ERROR("docker: get_network_stats: malloc failed!");
    sfree(stats->network_stats);
    stats->network_stats = NULL;
    return;
  }
  stats->network_stats->count = num_interfaces;
  for (int i = 0; i < num_interfaces; i++) {
    stats->network_stats->interfaces[i] = (interface_stats_t *)
        calloc(1, sizeof(interface_stats_t));
    if (stats->network_stats->interfaces[i] == NULL) {
      ERROR("docker: get_network_stats: malloc failed!");
      continue;
    }
    const char *interface_name = network_node->u.object.keys[i];
    stats->network_stats->interfaces[i]->name = sstrdup(interface_name);
    const char *interface_path[] = { interface_name, (const char *) 0 };
    yajl_val interface_node =
        yajl_tree_get(network_node, interface_path, yajl_t_object);
    if (!YAJL_IS_OBJECT(interface_node)) {
      ERROR("docker: JSON Error. \n");
      sfree(stats->network_stats->interfaces[i]->name);
      sfree(stats->network_stats->interfaces[i]);
      continue;
    }
    get_interface_stats(interface_node, stats->network_stats->interfaces[i]);
  }
}

// Parses the JSON response from the Docker STATS API and extracts metrics
// for memory, disk, CPU and networking interfaces.
static void extract_stats_from_response(char *response_buffer,
    container_stats_t ** stats, const char *container_id) {
  yajl_val node;
  char errbuf[1024];
  container_stats_t *ptr;
  ptr = (container_stats_t *) calloc(1, sizeof(container_stats_t));
  if (ptr == NULL) {
    ERROR("docker: extract_stats_from_response: malloc failed!");
    goto error;
  }
  node = yajl_tree_parse(response_buffer, errbuf, sizeof(errbuf));
  if (node == NULL) {
    if (strlen(errbuf)) {
      ERROR("docker: parse_error: %s.\n", errbuf);
    } else {
      ERROR("docker: parse_error.\n");
    }
    goto error;
  }
  get_memory_stats(node, ptr);
  get_blkio_stats(node, ptr);
  get_cpu_stats(node, ptr, container_id);
  get_network_stats(node, ptr);
  extract_string(node, "name", &(ptr->name));
  yajl_tree_free(node);
  *(stats) = ptr;
  return;

error:
  yajl_tree_free(node);
  free_stats(ptr);
}

static container_stats_t *get_stats_for_container(const char *container_id,
    const char *socket, const char *version) {
  char *response_buffer = (char *) calloc(RESPONSE_BUFFER_SIZE, sizeof(char));
  char *url = (char *) calloc(107, sizeof(char));
  if (response_buffer == NULL || url == NULL) {
    ERROR("docker: get_metrics_for_container: malloc failed.\n");
  }
  ssnprintf(url, 107, "http:/v%s/containers/%s/stats?stream=false", version,
      container_id);
  curl_get_json(response_buffer, RESPONSE_BUFFER_SIZE, url, socket);
  container_stats_t *ptr;
  extract_stats_from_response(response_buffer, &ptr, container_id);
  sfree(response_buffer);
  sfree(url);
  return ptr;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Funcitonality to dispatch Collectd Value lists with metrics.
//==============================================================================
//==============================================================================
//==============================================================================

static void dispatch_value_list(const char *hostname, const char *plugin,
  const char *plugin_instance, const char *type, const char *type_instance,
  meta_data_t * md, size_t count, value_t value, ...) {
  value_t values[count];
  value_list_t vl = VALUE_LIST_INIT;
  value_t val = value;
  va_list ap;
  va_start(ap, value);
  for (int i = 0; i < count; i++) {
    memcpy(&values[i], &val, sizeof(val));
    val = va_arg(ap, value_t);
  }
  va_end(ap);

  vl.values = values;
  vl.values_len = count;
  size_t plugin_name_len = 7 + strlen(plugin) + 1;
  char *plugin_name = (char *) calloc(plugin_name_len, sizeof(char));
  ssnprintf(plugin_name, plugin_name_len, "docker.%s", plugin);
  sstrncpy(vl.host, hostname, sizeof(vl.host));
  sstrncpy(vl.plugin, plugin_name, sizeof(vl.plugin));
  sstrncpy(vl.type, type, sizeof(vl.type));
  if (plugin_instance != NULL) {
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  }
  if (type_instance != NULL) {
    sstrncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));
  }
  if (md != NULL) {
    vl.meta = md;
  }
  plugin_dispatch_values(&vl);
  sfree(plugin_name);
}

static void dispatch_container_blkio_devices(const char *path,
    c_avl_tree_t *tree, char *hostname) {
  if (tree == NULL) {
    DEBUG("docker: No data for %s for Container: %s", path, hostname);
    return;
  }
  char *device;
  blkio_device_stats_t *value;
  c_avl_iterator_t *iterator = c_avl_get_iterator(tree);
  while (
      c_avl_iterator_next(iterator, (void **) &device, (void **) &value) == 0) {
    value_t values[2];
    values[0].derive = value->read;
    values[1].derive = value->write;
    dispatch_value_list(hostname, "disk", device, "disk_octets", NULL, NULL, 2,
        values[0], values[1]);
  }
  c_avl_iterator_destroy(iterator);
}

static void dispatch_container_blkio_stats(blkio_stats_t * stats,
    char *hostname) {
  c_avl_tree_t *result_ptrs[] = {
    stats->io_bytes,
  };

  assert(STATIC_ARRAY_SIZE(result_ptrs) == STATIC_ARRAY_SIZE(BLKIO_KEYS));
  for (int i = 0; i < STATIC_ARRAY_SIZE(BLKIO_KEYS); i++) {
    dispatch_container_blkio_devices(BLKIO_KEYS[i], result_ptrs[i], hostname);
  }
}

static void dispatch_container_cpu_stats(cpu_stats_t * stats, char *hostname) {
  for (int i = 0; i < stats->num_cpus; i++) {
    value_t used, idle, used_percent, idle_percent;
    unsigned int cpu_count = i + 1;	// 1 indexed
    char *cpu_num = (char *) calloc (11, sizeof(char));
    ssnprintf(cpu_num, 10, "%d", cpu_count);
    used.counter = stats->percpu_usage[i];
    idle.counter = stats->percpu_idle[i];
    used_percent.gauge = stats->percpu_percent_used[i];
    idle_percent.gauge = stats->percpu_percent_idle[i];
    dispatch_value_list(hostname, "cpu", cpu_num, "cpu", "used", NULL, 1, used);
    dispatch_value_list(hostname, "cpu", cpu_num, "cpu", "idle", NULL, 1, idle);
    dispatch_value_list(hostname, "cpu", cpu_num, "percent", "used", NULL, 1,
        used_percent);
    dispatch_value_list(hostname, "cpu", cpu_num, "percent", "idle", NULL, 1,
        idle_percent);
  }
}

static void dispatch_container_memory_stats(memory_stats_t * stats,
    char *hostname) {
  unsigned long bytes_results[] = {
    stats->usage,
    stats->free,
  };

  unsigned long percent_results[] = {
    stats->used_percentage,
    stats->free_percentage,
  };

  assert(STATIC_ARRAY_SIZE(bytes_results) == STATIC_ARRAY_SIZE(percent_results));
  for (int i = 0; i < STATIC_ARRAY_SIZE(bytes_results); i++) {
    value_t bytes, percent;
    bytes.gauge = bytes_results[i];
    percent.gauge = percent_results[i];
    dispatch_value_list(hostname, "memory", NULL, "memory",
        MEMORY_METRIC_TYPES[i], NULL, 1, bytes);
    dispatch_value_list(hostname, "memory", NULL, "percent",
        MEMORY_METRIC_TYPES[i], NULL, 1, percent);
  }
}

static void dispatch_container_interface_stats(interface_stats_t * stats,
    char *hostname) {
  unsigned long rx_results[] = {
    stats->rx_bytes,
    stats->rx_packets,
    stats->rx_errors,
  };

  unsigned long tx_results[] = {
    stats->tx_bytes,
    stats->tx_packets,
    stats->tx_errors,
  };

  const char *types[] = {
    "if_octets",
    "if_packets",
    "if_errors",
  };

  assert(STATIC_ARRAY_SIZE(rx_results) == STATIC_ARRAY_SIZE(INTERFACE_KEYS));
  assert(STATIC_ARRAY_SIZE(tx_results) == STATIC_ARRAY_SIZE(INTERFACE_KEYS));
  for (int i = 0; i < STATIC_ARRAY_SIZE(INTERFACE_KEYS); i++) {
    value_t values[2];
    values[0].derive = rx_results[i];
    values[1].derive = tx_results[i];
    dispatch_value_list(hostname, "interface", stats->name, types[i], NULL, NULL,
                        2, values[0], values[1]);
  }
}

static void dispatch_container_network_stats(network_stats_t * stats,
    char *hostname) {
  for (int i = 0; i < stats->count; i++) {
    if (stats->interfaces[i] != NULL) {
      dispatch_container_interface_stats(stats->interfaces[i], hostname);
    }
  }
}

static void dispatch_container_stats(container_resource_t * resource) {
  char *hostname = (char *) calloc (76, sizeof(char));
  ssnprintf(hostname, 75, "container.%s", resource->id);
  dispatch_container_blkio_stats(resource->stats->blkio_stats, hostname);
  dispatch_container_cpu_stats(resource->stats->cpu_stats, hostname);
  dispatch_container_memory_stats(resource->stats->memory_stats, hostname);
  dispatch_container_network_stats(resource->stats->network_stats, hostname);
  sfree(hostname);
}

static int dispatch_stats_all(void) {
  char **container_list = NULL;
  int count = get_container_list(&container_list, DOCKER_SOCKET,
				 DOCKER_VERSION);
  if (count == 0) {
    DEBUG("docker: No containers running on this machine.");
    goto leave;
  } else if (count == -1) {
    ERROR("docker: Unable to parse container information.");
    goto leave;
  }
  container_resource_t **containers = (container_resource_t **)
      calloc(count, sizeof(container_resource_t *));
  for (int i = 0; i < count; i++) {
    containers[i] = (container_resource_t *)
        calloc(1, sizeof(container_resource_t));
    containers[i]->id = container_list[i];
    containers[i]->stats = get_stats_for_container(containers[i]->id,
        DOCKER_SOCKET, DOCKER_VERSION);
  }
  for (int i = 0; i < count; i++) {
    if (containers[i]->stats != NULL) {
      dispatch_container_stats(containers[i]);
    }
  }
  for (int i = 0; i < count; i++) {
    if (containers[i]->stats != NULL) {
      free_stats(containers[i]->stats);
    }
    sfree(containers[i]);
  }
  sfree(containers);
 leave:
  free_list((void ***) &container_list, count);
  return 0;
}

//==============================================================================
//==============================================================================
//==============================================================================
// Collectd plugin load and configuration fucntionality.
//==============================================================================
//==============================================================================
//==============================================================================

static int docker_config(const char *key, const char *value) {
  if (strcmp(key, "Socket") == 0) {
    config_socket = (const char *) sstrdup(value);
    return 0;
  }

  if (strcmp(key, "Version") == 0) {
    config_version = (const char *) sstrdup(value);
    return 0;
  }
  WARNING("docker: Unknown config option found. Key: %s, Value: %s", key,
	  value);
  return -1;
}

static int docker_init(void) {
  if (DOCKER_VERSION == NULL) {
    DOCKER_VERSION = (const char *)
	(config_version != NULL ? config_version : DEFAULT_VERSION);
  }

  if (DOCKER_SOCKET == NULL) {
    DOCKER_SOCKET = (const char *)
	(config_socket != NULL ? config_socket : DEFAULT_SOCKET);
  }
  cpu_hist_values = c_avl_create((int(*)(const void *, const void *))&strcmp);
  if (cpu_hist_values == NULL) {
    ERROR("docker: c_avl_create failed.");
    return -1;
  }
  return 0;
}

static int docker_shutdown(void) {
  while (1) {
    void *key;
    void *value;
    if (c_avl_pick(cpu_hist_values, &key, &value) == 0) {
      sfree(key);
      sfree(((cpu_state_t *) value)->old_percpu_usage);
      sfree(value);
    } else break;
  }
  c_avl_destroy(cpu_hist_values);
  return 0;
}

void module_register(void) {
  plugin_register_config("docker", docker_config, config_keys, config_keys_num);
  plugin_register_init("docker", docker_init);
  plugin_register_read("docker", dispatch_stats_all);
  plugin_register_shutdown("docker", docker_shutdown);
}
