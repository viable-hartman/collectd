/**
 * collectd - src/mongo.c
 * Copyright (C) 2010 Ryan Cox
 * Copyright (C) 2012 Florian Forster
 * Copyright (C) 2013 John (J5) Palmieri
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; only version 2 of the License is applicable.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * Authors:
 *   Ryan Cox <ryan.a.cox at gmail.com>
 *   Florian Forster <octo at collectd.org>
 *   John (J5) Palmieri <j5 at stackdriver.com>
 *   Corey Kosak <kosak at google.com>
 **/

#include "collectd.h"
#include "common.h"
#include "plugin.h"
#include "utils_llist.h"

#include <errno.h>

#include <mongoc.h>
#include <bson.h>

static const char this_plugin_name[] = "mongodb";

typedef struct {
  char *hostname;
  char *server_uri;
  _Bool prefer_secondary_query;
} context_t;

static context_t *context_create(const char *hostname, const char *server_uri,
                                 _Bool prefer_secondary_query) {
  context_t *result = calloc(1, sizeof(*result));
  if (result == NULL) {
    ERROR("mongodb plugin: calloc failed.");
    return NULL;
  }
  result->hostname = strdup(hostname);
  result->server_uri = strdup(server_uri);
  result->prefer_secondary_query = prefer_secondary_query;
  return result;
}

static void context_destroy(context_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  sfree(ctx->server_uri);
  sfree(ctx->hostname);
  sfree(ctx);
}

static int mg_try_get_value(const bson_iter_t *iter, int ds_type, double scale,
                            value_t *result) {
  // The bson value can be one of a few types. Our strategy for dealing with
  // this is to store the value we extract in the variable of the most
  // appropriate type, then copy that value to the other variables. Then we
  // select the appropriate one of those three variables according to 'ds_type'.
  int64_t int64_value;
  uint64_t uint64_value;
  double double_value;

  // The bson value can be one of a few types. First store the in the variable of
  // the most appropriate type and then copy to the others.
  switch (bson_iter_type(iter)) {
    case BSON_TYPE_INT32:
      int64_value = bson_iter_int32(iter) * scale;
      uint64_value = int64_value;
      double_value = int64_value;
      break;

    case BSON_TYPE_INT64:
      int64_value = bson_iter_int64(iter) * scale;
      uint64_value = int64_value;
      double_value = int64_value;
      break;

    case BSON_TYPE_DOUBLE:
      double_value = bson_iter_double(iter) * scale;
      int64_value = double_value;
      uint64_value = double_value;
      break;

    default:
      ERROR("mongodb plugin: unrecognized iter type %d.", bson_iter_type(iter));
      return -1;
  }

  // Now store into the appropriate field of the result union.
  switch (ds_type) {
    case DS_TYPE_COUNTER:
      result->counter = uint64_value;
      break;

    case DS_TYPE_GAUGE:
      result->gauge = double_value;
      break;

    case DS_TYPE_DERIVE:
      result->derive = int64_value;
      break;

    case DS_TYPE_ABSOLUTE:
      result->absolute = uint64_value;
      break;

    default:
      ERROR("mongodb plugin: unrecognized ds_type %d.", ds_type);
      return -1;
  }
  return 0;
}

typedef struct {
  const char *key;
  const char *subkey;
  const char *type;
  const char *type_instance;
  int ds_type;
  double scale;
} parse_info_t;

static parse_info_t server_parse_infos[] = {
    { "opcounters", "insert", "total_operations", "insert", DS_TYPE_DERIVE, 1 },
    { "opcounters", "query", "total_operations", "query", DS_TYPE_DERIVE, 1 },
    { "opcounters", "update", "total_operations", "update", DS_TYPE_DERIVE, 1 },
    { "opcounters", "delete", "total_operations", "delete", DS_TYPE_DERIVE, 1 },
    { "opcounters", "getmore", "total_operations", "getmore", DS_TYPE_DERIVE, 1 },
    { "opcounters", "command", "total_operations", "command", DS_TYPE_DERIVE, 1 },

    { "mem", "mapped", "memory", "mapped", DS_TYPE_GAUGE, 1 << 20 },
    { "mem", "resident", "memory", "resident", DS_TYPE_GAUGE, 1 << 20 },
    { "mem", "virtual", "memory", "virtual", DS_TYPE_GAUGE, 1 << 20 },

    { "connections", "current", "current_connections", NULL, DS_TYPE_GAUGE, 1 }
};

static parse_info_t db_parse_infos[] = {
    { "collections", NULL, "gauge", "collections", DS_TYPE_GAUGE, 1 },
    { "objects", NULL, "gauge", "objects", DS_TYPE_GAUGE, 1 },
    { "numExtents", NULL, "gauge", "num_extents", DS_TYPE_GAUGE, 1 },
    { "indexes", NULL, "gauge", "indexes", DS_TYPE_GAUGE, 1 },
    { "dataSize", NULL, "bytes", "data", DS_TYPE_GAUGE, 1 },
    { "storageSize", NULL, "bytes", "storage", DS_TYPE_GAUGE, 1 },
    { "indexSize", NULL, "bytes", "index", DS_TYPE_GAUGE, 1 }
};

/*
 * Look up a statistic by key and (optional) subkey and then submits a value
 * list.Returns 0 if successful, >0 if key or subkey are not found, and <0 if
 * error.
 */
static int mg_submit_helper(
    const context_t *ctx, cdtime_t now, cdtime_t interval,
    const bson_t *document, const parse_info_t *ip,
    const char *plugin_instance) {
  bson_iter_t iter;
  if (!bson_iter_init(&iter, document)) {
    ERROR("mongodb plugin: bson_iter_init failed.");
    return -1;
  }

  if (!bson_iter_find(&iter, ip->key)) {
    ERROR("mongodb plugin: key %s not found.", ip->key);
    return 1;
  }

  if (ip->subkey != NULL) {
    bson_iter_recurse(&iter, &iter);
    if (!bson_iter_find(&iter, ip->subkey)) {
      ERROR("mongodb plugin: subkey %s.%s not found.", ip->key, ip->subkey);
      // Subkey not found.
      return 2;
    }
  }

  value_t value;
  if (mg_try_get_value(&iter, ip->ds_type, ip->scale, &value) != 0) {
    ERROR("mongodb plugin: Failed to parse value. Key is %s.%s",
          ip->key, ip->subkey);
    return -1;
  }

  value_list_t vl = {
      .values = &value,
      .values_len = 1,
      .time = now,
      .interval = interval
  };
  sstrncpy(vl.host, hostname_g, sizeof(vl.host));
  sstrncpy(vl.plugin, this_plugin_name, sizeof(vl.plugin));
  if (plugin_instance != NULL) {
    sstrncpy(vl.plugin_instance, plugin_instance, sizeof(vl.plugin_instance));
  }
  sstrncpy(vl.type, ip->type, sizeof(vl.type));
  if (ip->type_instance != NULL) {
    sstrncpy(vl.type_instance, ip->type_instance, sizeof(vl.type_instance));
  }

  if (plugin_dispatch_values(&vl) != 0) {
    ERROR("mongodb plugin: plugin_dispatch_values failed.");
    return -1;
  }
  return 0;
}

static int mg_parse_and_submit(
    const context_t *ctx, const bson_t *status, const char *plugin_instance,
    const parse_info_t *infos, size_t num_infos) {
  cdtime_t now = cdtime();
  cdtime_t interval = plugin_get_interval();

  size_t i;
  for (i = 0; i < num_infos; ++i) {
    const parse_info_t *ip = &infos[i];
    int result = mg_submit_helper(ctx, now, interval, status, ip,
                                  plugin_instance);
    if (result < 0) {
      ERROR("mongodb plugin: mg_submit_helper failed on key %s.%s.",
            ip->key, ip->subkey);
      return -1;
    }
  }
  return 0;
}

/*
 * Read statistics from the mongo database `db_name`.
 */
static int mg_process_database(
    const context_t *ctx, mongoc_client_t *client, const char *db_name) {
  bson_t *request = NULL;
  bson_t reply = BSON_INITIALIZER;
  bson_error_t error;
  int result = -1;  // Pessimistically assume failure.

  request = BCON_NEW("dbStats", BCON_INT32(1),
                     "scale", BCON_INT32(1));

  if (!mongoc_client_command_simple(client, db_name, request,
                                    NULL, &reply, &error)) {
    ERROR("mongodb plugin: dbStats command failed: %s.", error.message);
    goto leave;
  }

  if (mg_parse_and_submit(ctx, &reply, db_name, db_parse_infos,
                          STATIC_ARRAY_SIZE(db_parse_infos)) != 0) {
    ERROR("mongodb plugin: mg_parse_and_submit(db) failed.");
    goto leave;
  }

  result = 0;  // Success!

 leave:
  bson_destroy(&reply);
  bson_destroy(request);
  return result;
}

/**
 * Read the data from the MongoDB server.
 */
static int mg_read(user_data_t *user_data) {
  context_t *ctx = user_data->data;

  mongoc_client_t *client = NULL;
  bson_t server_reply = BSON_INITIALIZER;
  bson_error_t error;
  char **databases = NULL;
  int result = -1;  // Pessimistically assume failure.

  // Make a connection to the database.
  client = mongoc_client_new(ctx->server_uri);
  if (client == NULL) {
    ERROR("mongodb plugin: mongoc_client_new failed.");
    goto leave;
  }

  // Get the server status, parse it, and upload the response.
  if (!mongoc_client_get_server_status(client, NULL, &server_reply,
                                       &error)) {
    ERROR("mongodb plugin: mongoc_client_get_server_status failed: %s.",
          error.message);
    goto leave;
  }

  if (mg_parse_and_submit(ctx, &server_reply, NULL, server_parse_infos,
                          STATIC_ARRAY_SIZE(server_parse_infos)) != 0) {
    ERROR("mongodb plugin: mg_parse_and_submit(server) failed.");
    goto leave;
  }

  // Get the list of databases (which excludes "local", alas), then process each
  // database.
  databases = mongoc_client_get_database_names(client, &error);
  if (databases == NULL) {
    ERROR("mongodb plugin: mongoc_client_get_database_names failed: %s.",
          error.message);
    goto leave;
  }
  int i;
  for (i = 0; databases[i] != NULL; ++i) {
    if (mg_process_database(ctx, client, databases[i]) != 0) {
      // If there's an error, maybe it's only on one of the databases.
      ERROR("mongodb plugin: mg_process_database '%s' failed."
          " Continuing anyway...", databases[i]);
    }
  }
  // Now send process the "local" database.
  if (mg_process_database(ctx, client, "local") != 0) {
    ERROR("mongodb plugin: mg_process_database 'local' failed.");
  }

  result = 0;  // Success!

 leave:
  bson_strfreev (databases);
  bson_destroy(&server_reply);
  mongoc_client_destroy(client);
  return result;
}

/*
 * Initialize the mongoc driver.
 */
static int mg_init() {
  mongoc_init();
  return 0;
}

/*
 * Shut down the mongoc driver.
 */
static int mg_shutdown() {
  mongoc_cleanup();
  return 0;
}

static int mg_make_uri(char *buffer, size_t buffer_size,
                       const char *hostname, int port,
                       const char *user, const char *password) {
  char auth[256];
  auth[0] = 0;
  if (user != NULL) {
    int result = snprintf(auth, sizeof(auth), "%s:%s@", user, password);
    if (result < 0 || result >= sizeof(auth)) {
      ERROR("mongodb plugin: no space in buffer for user/password");
      return -1;
    }
  }

  const char *uri_hostname = hostname != NULL ? hostname : "localhost";

  int result = snprintf(buffer, buffer_size, "mongodb://%s%s:%d/admin",
                       auth, uri_hostname, port);
  if (result < 0 || result >= buffer_size) {
    ERROR("mongodb plugin: buffer not big enough to build URI.");
    return -1;
  }
  return 0;
}

/*
 * Read the configuration. If successful, register a read callback.
 */
static int mg_config(oconfig_item_t *ci) {
  ERROR("mg_config: Inside mg_config");
  char *hostname = NULL;
  int port = MONGOC_DEFAULT_PORT;
  char *user = NULL;
  char *password = NULL;
  _Bool prefer_secondary_query = 0;
  context_t *ctx = NULL;
  int result = -1;  // Pessimistically assume failure.

  int parse_errors = 0;

  int i;
  for (i = 0; i < ci->children_num; ++i) {
    oconfig_item_t *child = &ci->children[i];

    const char *error_template =
        "mongodb plugin: Error parsing \"%s\" in config.";

    if (strcasecmp("Host", child->key) == 0) {
      if (cf_util_get_string(child, &hostname) != 0) {
        ERROR(error_template, "Host");
        ++parse_errors;
        continue;
      }
    } else if (strcasecmp("Port", child->key) == 0) {
      if (cf_util_get_int(child, &port) != 0) {
        ERROR(error_template, "Port");
        ++parse_errors;
        continue;
      }
    } else if (strcasecmp("User", child->key) == 0) {
      if (cf_util_get_string(child, &user) != 0) {
        ERROR(error_template, "User");
        ++parse_errors;
        continue;
      }
    } else if (strcasecmp("Password", child->key) == 0) {
      if (cf_util_get_string(child, &password) != 0) {
        ERROR(error_template, "Password");
        ++parse_errors;
        continue;
      }
    } else if (strcasecmp("PreferSecondaryQuery", child->key) == 0) {
      if (cf_util_get_boolean(child, &prefer_secondary_query) != 0) {
        ERROR(error_template, "PreferSecondaryQuery");
        ++parse_errors;
        continue;
      }
    } else if (strcasecmp("AllowSecondaryQuery", child->key) == 0) {
      WARNING("mongodb plugin: config option 'AllowSecondaryQuery' is"
          " deprecated. Use 'PreferSecondaryQuery' instead.");
      if (cf_util_get_boolean(child, &prefer_secondary_query) != 0) {
        ERROR(error_template, "AllowSecondaryQuery");
        ++parse_errors;
        continue;
      }
    } else {
      ERROR("mongodb plugin: unrecognized key \"%s\" in config.",
            child->key);
      ++parse_errors;
    }
  }
  if (parse_errors > 0) {
    goto leave;
  }
  if ((user == NULL && password != NULL) || (user != NULL && password == NULL)){
    ERROR("mongodb plugin: User and Password in the config either need to both"
        " be specified or both be unspecified.");
    goto leave;
  }

  char uri[1024];
  if (mg_make_uri(uri, sizeof(uri), hostname, port, user, password) != 0) {
    ERROR("mongodb plugin: mg_make_uri failed");
    goto leave;
  }

  const char *stats_hostname = hostname != NULL ? hostname : hostname_g;
  ctx = context_create(stats_hostname, uri, prefer_secondary_query);
  if (ctx == NULL) {
    ERROR("mongodb plugin: context_create failed.");
    goto leave;
  }

  user_data_t user_data = {
      .data = ctx,
      .free_func = (void(*)(void*))&context_destroy
  };

  if (plugin_register_complex_read(NULL, this_plugin_name,
                                   &mg_read, NULL, &user_data) != 0) {
    ERROR("mongodb plugin: plugin_register_complex_read failed.");
    goto leave;
  }

  ctx = NULL;  // Owned by plugin system now.
  result = 0;  // Success!

 leave:
  context_destroy(ctx);
  sfree(password);
  sfree(user);
  sfree(hostname);
  return result;
}

/* Register this module with collectd */
void module_register(void)
{
  if (plugin_register_init(this_plugin_name, &mg_init) != 0) {
    ERROR("mongodb plugin: plugin_register_init failed.");
    return;
  }
  if (plugin_register_complex_config(this_plugin_name, &mg_config) != 0) {
    ERROR("mongodb plugin: plugin_register_complex_config failed.");
    return;
  }
  if (plugin_register_shutdown (this_plugin_name, &mg_shutdown) != 0) {
    ERROR("mongodb plugin: plugin_register_shutdown failed.");
    return;
  }
}
