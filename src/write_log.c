/**
 * collectd - src/write_log.c
 * Copyright (C) 2015       Pierre-Yves Ritschard
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
 *   Pierre-Yves Ritschard <pyr at spootnik.org>
 *
 **/

#include "collectd.h"

#include "common.h"
#include "plugin.h"

#include "utils_format_graphite.h"
#include "utils_format_json.h"

#include <netdb.h>

#define WL_BUF_SIZE 16384

#define WL_FORMAT_GRAPHITE 1
#define WL_FORMAT_JSON 2
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======

<<<<<<< HEAD
/* Plugin:WriteLog has to also operate without a config, so use a global. */
int wl_format = WL_FORMAT_GRAPHITE;
=======
>>>>>>> Completes rebase

<<<<<<< HEAD
=======
=======

>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
>>>>>>> Address review comments:
static int wl_write_graphite (const data_set_t *ds, const value_list_t *vl)
{
    char buffer[WL_BUF_SIZE] = { 0 };
    int status;

    if (0 != strcmp (ds->type, vl->type))
    {
        ERROR ("write_log plugin: DS type does not match value list type");
        return -1;
    }
<<<<<<< HEAD
>>>>>>> Add optional configuration to write_log; allow writing JSON.
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Completes rebase

=======
>>>>>>> Adds upstream write_log
/* Plugin:WriteLog has to also operate without a config, so use a global. */
int wl_format = WL_FORMAT_GRAPHITE;

static int wl_write_graphite(const data_set_t *ds, const value_list_t *vl) {
  char buffer[WL_BUF_SIZE] = {0};
  int status;

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Adds upstream write_log
  if (0 != strcmp(ds->type, vl->type)) {
    ERROR("write_log plugin: DS type does not match value list type");
    return -1;
  }

  status = format_graphite(buffer, sizeof(buffer), ds, vl, NULL, NULL, '_', 0);
  if (status != 0) /* error message has been printed already. */
    return status;

  INFO("write_log values:\n%s", buffer);

  return 0;
<<<<<<< HEAD
} /* int wl_write_graphite */

static int wl_write_json(const data_set_t *ds, const value_list_t *vl) {
  char buffer[WL_BUF_SIZE] = {0};
  size_t bfree = sizeof(buffer);
  size_t bfill = 0;

  if (0 != strcmp(ds->type, vl->type)) {
    ERROR("write_log plugin: DS type does not match value list type");
    return -1;
  }

  format_json_initialize(buffer, &bfill, &bfree);
  format_json_value_list(buffer, &bfill, &bfree, ds, vl,
                         /* store rates = */ 0);
  format_json_finalize(buffer, &bfill, &bfree);

  INFO("write_log values:\n%s", buffer);

  return 0;
} /* int wl_write_json */

static int wl_write(const data_set_t *ds, const value_list_t *vl,
                    __attribute__((unused)) user_data_t *user_data) {
  int status = 0;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
=======
>>>>>>> Completes rebase
    return (0);
=======
>>>>>>> Adds upstream write_log
} /* int wl_write_graphite */

static int wl_write_json(const data_set_t *ds, const value_list_t *vl) {
  char buffer[WL_BUF_SIZE] = {0};
  size_t bfree = sizeof(buffer);
  size_t bfill = 0;

  if (0 != strcmp(ds->type, vl->type)) {
    ERROR("write_log plugin: DS type does not match value list type");
    return -1;
  }

  format_json_initialize(buffer, &bfill, &bfree);
  format_json_value_list(buffer, &bfill, &bfree, ds, vl,
                         /* store rates = */ 0);
  format_json_finalize(buffer, &bfill, &bfree);

  INFO("write_log values:\n%s", buffer);

  return 0;
} /* int wl_write_json */

<<<<<<< HEAD
static int wl_write (const data_set_t *ds, const value_list_t *vl,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        __attribute__ ((unused)) user_data_t *user_data)
{
    int status = 0;

    if (wl_format == WL_FORMAT_GRAPHITE)
    {
        status = wl_write_graphite (ds, vl);
    }
    else if (wl_format == WL_FORMAT_JSON)
=======
        user_data_t *user_data)
=======
        __attribute__ ((unused)) user_data_t *user_data)
>>>>>>> Address review comments:
=======
        user_data_t *user_data)
>>>>>>> Completes rebase
{
    int status = 0;
    int mode = (int) (size_t) user_data->data;

    if (mode == WL_FORMAT_GRAPHITE)
    {
        status = wl_write_graphite (ds, vl);
    }
<<<<<<< HEAD
<<<<<<< HEAD
    else if (mode == WL_FORMAT_JSON)
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
    else if (wl_format == WL_FORMAT_JSON)
>>>>>>> Address review comments:
    {
        status = wl_write_json (ds, vl);
    }
>>>>>>> Add optional configuration to write_log; allow writing JSON.
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
    else if (mode == WL_FORMAT_JSON)
    {
        status = wl_write_json (ds, vl);
    }
>>>>>>> Completes rebase
=======
static int wl_write(const data_set_t *ds, const value_list_t *vl,
                    __attribute__((unused)) user_data_t *user_data) {
  int status = 0;
>>>>>>> Adds upstream write_log

  if (wl_format == WL_FORMAT_GRAPHITE) {
    status = wl_write_graphite(ds, vl);
  } else if (wl_format == WL_FORMAT_JSON) {
    status = wl_write_json(ds, vl);
  }

  return status;
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
static int wl_config(oconfig_item_t *ci) /* {{{ */
{
  bool format_seen = false;

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

    if (strcasecmp("Format", child->key) == 0) {
      char str[16];

      if (cf_util_get_string_buffer(child, str, sizeof(str)) != 0)
        continue;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
static int wl_config (oconfig_item_t *ci) /* {{{ */
{
    _Bool format_seen = 0;

=======
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======
static int wl_config (oconfig_item_t *ci) /* {{{ */
{
<<<<<<< HEAD
    int mode = 0;
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
    _Bool format_seen = 0;

>>>>>>> Address review comments:
=======
static int wl_config (oconfig_item_t *ci) /* {{{ */
{
    int mode = 0;
>>>>>>> Completes rebase
    for (int i = 0; i < ci->children_num; i++)
    {
        oconfig_item_t *child = ci->children + i;

        if (strcasecmp ("Format", child->key) == 0)
        {
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Address review comments:
            char str[16];

            if (cf_util_get_string_buffer (child, str, sizeof (str)) != 0)
                continue;

            if (format_seen)
<<<<<<< HEAD
=======
=======
>>>>>>> Completes rebase
            char *mode_str = NULL;
            if ((child->values_num != 1)
                || (child->values[0].type != OCONFIG_TYPE_STRING))
            {
                ERROR ("write_log plugin: Option `%s' requires "
                    "exactly one string argument.", child->key);
                return (-EINVAL);
            }
            if (mode != 0)
<<<<<<< HEAD
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
>>>>>>> Address review comments:
=======
>>>>>>> Completes rebase
            {
                WARNING ("write_log plugin: Redefining option `%s'.",
                    child->key);
            }
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> Address review comments:
            format_seen = 1;

            if (strcasecmp ("Graphite", str) == 0)
                wl_format = WL_FORMAT_GRAPHITE;
            else if (strcasecmp ("JSON", str) == 0)
                wl_format = WL_FORMAT_JSON;
<<<<<<< HEAD
            else
            {
                ERROR ("write_log plugin: Unknown format `%s' for option `%s'.",
                    str, child->key);
=======
            mode_str = child->values[0].value.string;
            if (strcasecmp ("Graphite", mode_str) == 0)
                mode = WL_FORMAT_GRAPHITE;
            else if (strcasecmp ("JSON", mode_str) == 0)
                mode = WL_FORMAT_JSON;
            else
            {
                ERROR ("write_log plugin: Unknown mode `%s' for option `%s'.",
                    mode_str, child->key);
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
            else
            {
                ERROR ("write_log plugin: Unknown format `%s' for option `%s'.",
                    str, child->key);
>>>>>>> Address review comments:
=======
            mode_str = child->values[0].value.string;
            if (strcasecmp ("Graphite", mode_str) == 0)
                mode = WL_FORMAT_GRAPHITE;
            else if (strcasecmp ("JSON", mode_str) == 0)
                mode = WL_FORMAT_JSON;
            else
            {
                ERROR ("write_log plugin: Unknown mode `%s' for option `%s'.",
                    mode_str, child->key);
>>>>>>> Completes rebase
                return (-EINVAL);
            }
        }
        else
        {
            ERROR ("write_log plugin: Invalid configuration option: `%s'.",
                child->key);
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
            return (-EINVAL);
        }
    }
=======
        }
    }
=======
        }
    }
>>>>>>> Completes rebase
    if (mode == 0)
        mode = WL_FORMAT_GRAPHITE;
=======
static int wl_config(oconfig_item_t *ci) /* {{{ */
{
  bool format_seen = false;
>>>>>>> Adds upstream write_log

  for (int i = 0; i < ci->children_num; i++) {
    oconfig_item_t *child = ci->children + i;

<<<<<<< HEAD
    plugin_register_write ("write_log", wl_write, &ud);
<<<<<<< HEAD
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
            return (-EINVAL);
        }
    }
>>>>>>> Address review comments:
=======
>>>>>>> Completes rebase

    return (0);
} /* }}} int wl_config */

void module_register (void)
{
    plugin_register_complex_config ("write_log", wl_config);
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    /* If config is supplied, the global wl_format will be set. */
    plugin_register_write ("write_log", wl_write, NULL);
}
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
<<<<<<< HEAD
=======

    user_data_t ud = {
        .data = (void *) (size_t) WL_FORMAT_GRAPHITE,
        .free_func = NULL
    };

    plugin_register_write ("write_log", wl_write, &ud);
=======
    /* If config is supplied, the global wl_format will be set. */
    plugin_register_write ("write_log", wl_write, NULL);
>>>>>>> Address review comments:
}
>>>>>>> Add optional configuration to write_log; allow writing JSON.
>>>>>>> Add optional configuration to write_log; allow writing JSON.
=======
>>>>>>> Removes HEAD tag (atom bug) from remaining files... I think.
=======

    user_data_t ud = {
        .data = (void *) (size_t) WL_FORMAT_GRAPHITE,
        .free_func = NULL
    };

    plugin_register_write ("write_log", wl_write, &ud);
}
>>>>>>> Completes rebase
=======
    if (strcasecmp("Format", child->key) == 0) {
      char str[16];

      if (cf_util_get_string_buffer(child, str, sizeof(str)) != 0)
        continue;
>>>>>>> Adds upstream write_log

      if (format_seen) {
        WARNING("write_log plugin: Redefining option `%s'.", child->key);
      }
      format_seen = true;

      if (strcasecmp("Graphite", str) == 0)
        wl_format = WL_FORMAT_GRAPHITE;
      else if (strcasecmp("JSON", str) == 0)
        wl_format = WL_FORMAT_JSON;
      else {
        ERROR("write_log plugin: Unknown format `%s' for option `%s'.", str,
              child->key);
        return -EINVAL;
      }
    } else {
      ERROR("write_log plugin: Invalid configuration option: `%s'.",
            child->key);
      return -EINVAL;
    }
  }

  return 0;
} /* }}} int wl_config */

void module_register(void) {
  plugin_register_complex_config("write_log", wl_config);
  /* If config is supplied, the global wl_format will be set. */
  plugin_register_write("write_log", wl_write, NULL);
}
