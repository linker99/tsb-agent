#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <httcutils/debug.h>

char *g_cb_buff = NULL;

#ifdef HTTCUTILS_DEBUG
const httc_util_log_config_t config_default =
    {
        .level = HTTC_UTIL_LOG_LEVEL_DEBUG,
        .subject = DEFAULT_LOG_SUBJECT,
        .filename = DEFAULT_DEBUG_LOG_FILE,
        .max_size = MAX_LOG_SIZE, // 256M
        .output = TO_FILE,
};

httc_util_log_config_t config_runtime  =
    {
        .level = HTTC_UTIL_LOG_LEVEL_DEBUG,
        .subject = DEFAULT_LOG_SUBJECT,
        .filename = DEFAULT_DEBUG_LOG_FILE,
        .max_size = MAX_LOG_SIZE, // 256M
        .output = TO_FILE,
};
#else
const httc_util_log_config_t config_default =
    {
        .level = HTTC_UTIL_LOG_LEVEL_ERROR,
        .subject = DEFAULT_LOG_SUBJECT,
        .filename = DEFAULT_LOG_FILE,
        .max_size = MAX_LOG_SIZE, // 256M
        .output = TO_FILE,
};

httc_util_log_config_t config_runtime =
    {
        .level = HTTC_UTIL_LOG_LEVEL_ERROR,
        .subject = DEFAULT_LOG_SUBJECT,
        .filename = DEFAULT_LOG_FILE,
        .max_size = MAX_LOG_SIZE, // 256M
        .output = TO_FILE,
};
#endif

pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

char *log_label[] = {"ERROR", "INFO", "DEBUG"};

httc_util_log_config_t *gp_config = &config_runtime;

FILE *gp_log_file;

void httc_util_log_init(void)
{
    pthread_mutex_lock(&g_log_mutex);
    config_runtime = config_default;
    gp_config = &config_runtime;
    pthread_mutex_unlock(&g_log_mutex);
}

int httc_util_log_set(const struct httc_util_log_config *in_config)
{

    int ret = LOG_OK;

    if (in_config == NULL)
    {
        return LOG_CONFIG_NULL;
    }

    if (in_config->output > TO_CALLBACK || in_config->output < TO_FILE)
    {
        return LOG_CONFIG_OUTPUT_INVALID;
    }

    if (in_config->output == TO_FILE)
    {
        if (in_config->filename == NULL)
        {
            return LOG_CONFIG_FILENAME_NULL;
        }
        if (strlen(in_config->filename) > MAX_FILENAME)
        {
            return LOG_CONFIG_FILENAME_TOO_LONG;
        }
        if (in_config->max_size < MIN_LOG_SIZE || in_config->max_size > MAX_LOG_SIZE)
        {
            return LOG_CONFIG_MAX_SIZE_INVALID;
        }
    }
    else if (in_config->output == TO_CALLBACK)
    {
        if (in_config->callback == NULL)
        {
            return LOG_CONFIG_CALLBACK_NULL;
        }
    }
    // 设置日志等级
    if (in_config->level > HTTC_UTIL_LOG_LEVEL_DEBUG || in_config->level <= HTTC_UTIL_LOG_LEVEL_NONE)
    {
        return LOG_CONFIG_LEVEL_INVALID;
    }
    if (in_config->subject == NULL)
    {
        return LOG_CONFIG_SUBJECT_NULL;
    }
    if (strlen(in_config->subject) > MAX_SUBJECT)
    {
        return LOG_CONFIG_SUBJECT_TOO_LONG;
    }

    if (!gp_config)
    {
        httc_util_log_init();
    }
    // 保存配置信息
    pthread_mutex_lock(&g_log_mutex);
    *gp_config = *in_config;
    pthread_mutex_unlock(&g_log_mutex);
    return ret;
}

int httc_util_log_get(struct httc_util_log_config *config)
{
    if (!config)
    {
        return LOG_CONFIG_NULL;
    }
    if (!gp_config)
    {
        return LOG_CONFIG_UNSET;
    }
    pthread_mutex_lock(&g_log_mutex);
    *config = *gp_config;
    pthread_mutex_unlock(&g_log_mutex);
    return LOG_OK;
}

int httc_util_log_close(void)
{
    pthread_mutex_lock(&g_log_mutex);
    if (gp_config)
        gp_config->level = HTTC_UTIL_LOG_LEVEL_NONE;
    if (g_cb_buff)
    {
        free(g_cb_buff);
        g_cb_buff = NULL;
    }
    pthread_mutex_unlock(&g_log_mutex);
    return LOG_OK;
}

int httc_util_log_reset(void)
{
    int ret = LOG_OK;
    pthread_mutex_lock(&g_log_mutex);
    if (gp_log_file)
    {
        fclose(gp_log_file);
        gp_log_file = NULL;
        remove(gp_config->filename);
        char *oldlog = calloc(strlen(gp_config->filename) + 5, 1);
        if (oldlog)
        {
            strncpy(oldlog, gp_config->filename, strlen(gp_config->filename));
            strcat(oldlog, ".old");
            remove(oldlog);
            free(oldlog);
        }
        else
        {
            fprintf(stderr, "calloc error");
            ret = LOG_CONFIG_CALLOC_ERR;
        }
    }
    pthread_mutex_unlock(&g_log_mutex);
    httc_util_log_close();
    httc_util_log_init();
    return ret;
}

void httc_util_dump_hex(const char *name, void *p, int bytes)
{
    int i = 0;
    uint8_t *data = p;
    int hexlen = 0;
    int chrlen = 0;
    uint8_t hexbuf[49] = {0};
    uint8_t chrbuf[17] = {0};
    uint8_t dumpbuf[128] = {0};

    printf("%s length=%d:\n", name, bytes);

    for (i = 0; i < bytes; i++)
    {
        hexlen += sprintf((char *)&hexbuf[hexlen], "%02X ", data[i]);
        chrlen += sprintf((char *)&chrbuf[chrlen], "%c", ((data[i] >= 33) && (data[i] <= 126)) ? (unsigned char)data[i] : '.');
        if (i % 16 == 15)
        {
            sprintf((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
            printf("%s\n", dumpbuf);
            hexlen = 0;
            chrlen = 0;
        }
    }

    if (i % 16 != 0)
    {
        sprintf((char *)&dumpbuf[0], "%08X: %-49s%-17s", i / 16 * 16, hexbuf, chrbuf);
        printf("%s\n", dumpbuf);
    }
}
