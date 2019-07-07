/* Author: mgood7123 (Matthew James Good) http://github.com/mgood7123 */

#ifndef __SHELL_ENV
#define __SHELL_ENV

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef libstring
char *
strcatb(char *dest,
       const char *src)
{
    char *cptr = dest;

    while (*cptr) {
        cptr++;
    }
    while (*src) {
        *cptr++ = *src++;
    }
    *cptr = *src;

    return dest;
}

#endif


typedef char ** env_t;

extern env_t environ;
env_t environ_default;

static int env__size(env_t env) { 
    if (!env) return 0;
	int i;
	for (i = 0; env[i] != 0; i++);
	return i;
}

char *
env__get(env_t env, const char *envtarget)
{
    if (!env) return NULL;
    const char * STTR = envtarget;
    int i = 1;
    char *s = *env;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /* fprintf(stderr, "trying \"%s\"\2\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                    char * n2 = strchr(s, '=');
					char * y2 = strdup(y);
					if (n2 != NULL) y2[strlen(s)-strlen(n2)] = 0;
                    if (strcmp(y2, STTR) == 0)
                        {
							free(y2);
                            free(y);
                            return strchr(s, '=')+1;
                        }
					free(y2);
					break;
                }
            free(y);
        }
        s = *(env+i);
    }
/* 	fprintf(stderr, "  \"%s\" COULD NOT BE FOUND\n", STTR); */
	free(s);
	return NULL;
}

char *
env__get_name(env_t env, const char *envtarget)
{
    if (!env) return NULL;
    const char * STTR = envtarget;
    int i = 1;
    char *s = *env;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /* fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
					char * n2 = strchr(s, '=');
					char * y2 = strdup(y);
					if (n2 != NULL) y2[strlen(s)-strlen(n2)] = 0;
                    if (strcmp(y2, STTR) == 0)
                        {
							free(y2);
							char * n = strchr(s, '=');
							if (n != NULL) y[strlen(s)-strlen(n)] = 0;
							return y;
                        }
					free(y2);
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
/* 	fprintf(stderr, "  \"%s\" COULD NOT BE FOUND\n", STTR); */
	free(s);
	return NULL;
}

void
env__print(env_t env, const char *envtarget)
{
    if (!env) return;
    const char * STTR = envtarget;
    int i = 1;
    char *s = *env;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                    char * NAME = pch;
                    if (strcmp(NAME,STTR) == 0 )
                        {
                            char * pch = strtok (NULL, "=");
                            char * VALUE = pch;
                            puts(s);
                            free(y);
                            return;
                        }
                    if (strcmp(NAME,STTR) != 0 )
                        {
                        }
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	free(s);
	return;
}

char *
env__return(env_t env, const char *envtarget)
{
    if (!env) return NULL;
    const char * STTR = envtarget;
    int i = 1;
    char *s = *env;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                    char * NAME = pch;
                    if (strcmp(NAME,STTR) == 0 )
                        {
                            free(y);
                            return s;
                        }
                    if (strcmp(NAME,STTR) != 0 )
                        {
                        }
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	fprintf(stderr, "  \"%s\" COULD NOT BE FOUND\n", STTR);
	free(s);
	return (char*)"(null)";
}

int
env__getposition(env_t env, const char *envtarget)
{
    if (!env) return -1;
    const char * STTR = envtarget;
    int i = 1;
    char *s = *env;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                    char * NAME = pch;
                    if (strcmp(NAME,STTR) == 0 )
                        {
                            free(y);
                            return i;
                        }
                    if (strcmp(NAME,STTR) != 0 )
                        {
                        }
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	free(s);
	return -1;
}

env_t env__new() {
	env_t envempty = malloc(1*sizeof(*envempty));
	envempty[0] = NULL;
	return envempty;
}

void env__free(env_t env) {
    if (!env) return;
	env_t ep;
    for (ep = env; *ep; ep++) {
        memset(*ep, 0, strlen(*ep));
        free(*ep);
        *ep = NULL;
    }
    *env = NULL;
	free(env);
    env = NULL;
}

void env__clear(env_t env) {
	env__free(env);
	env = env__new();
}

void env__list(env_t env) {
    if (!env) return;
	env_t ep;
	for (ep = env; *ep; ep++) printf("%s\n", *ep);
}

env_t env__add(env_t env, const char * string) {
    /* if (!env) env = env__new();
	duplicate entries should be ignored */
	char * name = env__get_name(env, string);
	if (env__getposition(env, name==NULL?string:name) != -1) return env;
	env_t array_tmp;
	size_t i = env__size(env);
	array_tmp = realloc(env, ((i+2)*sizeof(char*)));
    if (array_tmp == NULL) {
        fprintf(stderr, "failed to resize env");
        return env;
    } else {
        env = array_tmp;
    }
    env[i] = strdup(string);
    env[i+1] = NULL;
    return env;
}

env_t env__add2(env_t env, const char * string) {
    /*if (!env) env = env__new(); */
	env_t array_tmp;
	size_t i = env__size(env);
	array_tmp = realloc(env, ((i+2)*sizeof(char*)));
    if (array_tmp == NULL) {
        fprintf(stderr, "failed to resize env");
        return env;
    } else {
        env = array_tmp;
    }
    env[i] = strdup(string);
    env[i+1] = NULL;
    return env;
}

env_t env__copy(env_t env)
{
    if (!env) return env__new();
	env_t ret = env__new();
	int i;
	for (i = 0; i < env__size(env); i++) ret = env__add(ret, env[i]);
	return ret;
}

env_t env__add_env(env_t env, char * name, env_t * variable) {
    env_t envtmp = env__copy(env);
    int len = 1+strlen(name)+strlen("=")+strlen("0x")+(sizeof(variable)*2); /* (0x00 to 0xFF) == 1 byte */
    char * str = malloc(len);
    memset(str, 0, len);
    snprintf(str,len, "%s=%p",name, variable);
    envtmp = env__add(envtmp, str);
    memset(str, 0, len);
    free(str);
    env__free(env);
    env = env__copy(envtmp);
    env__free(envtmp);
    return env;
}

env_t * env__get_env(env_t env, char * s) {
	char * n = env__get(env, s);
	if (n) {
		env_t b;
		sscanf(n,"%p",b);
		return *b;
	}
}

env_t env__remove(env_t env, const char * string) {
	/* we rebuild the entire environment */
	env_t envtmp = env__copy(env);
	env_t envempty = env__new();
    int i = 1;
    char *s = *envtmp;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                    if (strcmp(pch,string) != 0 ) {
                    	envempty = env__add(envempty, s);
                    }
                    else printf("\nremoving %s\n\n", string);
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	free(s);
    env__free(env);
	env = env__copy(envempty);
	env__free(envempty);
	env__free(envtmp);
	return env;
}

env_t env__replace(env_t env, const char * string, const char * string2) {
	/* we rebuild the entire environment */
	env_t envtmp = env__copy(env);
	env_t envempty = env__new();
    int i = 1;
    char *s = *envtmp;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
                	/*printf(" does %s == %s\n", pch, string); */
                    if (strcmp(pch,string) != 0 ) {
                    	envempty = env__add(envempty, s);
                    }
                    else {
                    	printf("replacing %s with %s=%s\n\n", s, pch, string2);
                    	char * tmp = malloc(strlen(pch)+strlen("=")+strlen(string2));
                    	tmp = strcatb(tmp, pch);
                    	tmp = strcatb(tmp, "=");
                    	tmp = strcatb(tmp, string2);
                    	envempty = env__add(envempty, tmp);
                    	free(tmp);
                    }
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	free(s);
    env__free(env);
	env = env__copy(envempty);
	env__free(envempty);
	env__free(envtmp);
	return env;
}


env_t env__append(env_t env, const char * name, const char * string) {
    if (!env) return env__new();
	/* we rebuild the entire environment */
	env_t envtmp = env__copy(env);
	env_t envempty = env__new();
    int i = 1;
    char *s = *envtmp;

    for (; s; i++) {
        if (s)
        {
            char * pch;
            char * y = (char *)malloc(strlen(s) + 1);
            strcpy(y,s);
            /*fprintf(stderr, "trying \"%s\"\n", y); */
            pch = strtok (y,"=");
            while (pch != NULL)
                {
/*                 	printf("does %s == %s (%s)\n", pch, name, string); */
                    if (strcmp(pch,name) != 0 ) {
                    	envempty = env__add(envempty, s);
                    }
                    else {
/*                     	printf("appending %s to %s\n\n", string, s); */
                    	char * tmp = malloc(strlen(s)+strlen(string));
                    	tmp = strcatb(tmp, s);
                    	tmp = strcatb(tmp, string);
                    	envempty = env__add(envempty, tmp);
                    	free(tmp);
                    }
                    break;
                }
            free(y);
        }
        s = *(env+i);
    }
	free(s);
    env__free(env);
	env = env__copy(envempty);
	env__free(envempty);
	env__free(envtmp);
	return env;
}

env_t env__append_env(env_t env1, env_t env2) {
 	if (!env1 && !env2) return env__new();
    if (!env2) return env1;
	/* we rebuild the entire environment */
 	env_t envtmp = env__copy(env1);
	int i;
	for (i = 0; i < env__size(env1); i++) envtmp = env__add(envtmp, env1[i]);
	for (i = 0; i < env__size(env2); i++) envtmp = env__add(envtmp, env2[i]);
	env__free(env1);
	env1 = env__copy(envtmp);
	env__free(envtmp);
	return env1;
}

env_t env__clean(env_t env1) {
	env_t envtmp = env__new();
	int i;
	for (i = 0; i < env__size(env1); i++) {
		char * name = env__get_name(env1, env1[i]);
		char * returned = env__return(env1, name);
		envtmp = env__add(envtmp, returned);
		free(name);
	}
	env__free(env1);
	env1 = env__copy(envtmp);
	env__free(envtmp);
	return env1;
}

#endif
