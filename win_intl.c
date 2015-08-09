/*
 * intl
 *
 * This file is placed in the public domain.
 */

#include <windows.h>

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iconv.h>

#define DEFAULT_DIRNAME "\\share\\locale"

#if !defined(LC_MESSAGES)
# define LC_MESSAGES 9999
#endif

char *gettext(const char *msgid);
char *dgettext(const char *domainname, const char *msgid);
char *dcgettext(const char *domainname, const char *msgid, int category);
char *textdomain(const char *domainname);
char *bindtextdomain(const char *domainname, const char *dirname);
char *bind_textdomain_codeset(const char *domainname, const char *codeset);

struct Slist {
    struct Slist *next;
    void *data;
};

static struct Slist *Slist_add(struct Slist **phead);
static void Slist_delete(struct Slist **phead, struct Slist *x);

struct Domain {
    char *domainname;
    char *dirname;
    char *codeset;
    struct Slist *catalog_head;
};

static struct Domain *Domain_new();
static void Domain_delete(struct Domain *self);
static BOOL Domain_set_domainname(struct Domain *self, const char *domainname);
static const char *Domain_get_domainname(struct Domain *self);
static BOOL Domain_set_dirname(struct Domain *self, const char *dirname);
static const char *Domain_get_dirname(struct Domain *self);
static BOOL Domain_set_codeset(struct Domain *self, const char *codeset);
static const char *Domain_get_codeset(struct Domain *self);
static const char *Domain_cgettext(struct Domain *self, const char *msgid, int category);
static struct Catalog *Domain_getcatalog(struct Domain *self, int category);
static const char *Domain_mo_path(struct Domain *self, int category, const char *locale);

struct Catalog {
    char *locale;
    int category;
    char *codeset;
    int size;
    char **original;
    char **translation;
    char **encoded;
    char *modata;
    char *mocodeset;
};

static struct Catalog *Catalog_new();
static void Catalog_delete(struct Catalog *self);
static BOOL Catalog_set_locale(struct Catalog *self, const char *locale);
static const char *Catalog_get_locale(struct Catalog *self);
static BOOL Catalog_set_category(struct Catalog *self, int category);
static int Catalog_get_category(struct Catalog *self);
static BOOL Catalog_set_codeset(struct Catalog *self, const char *codeset);
static const char *Catalog_get_codeset(struct Catalog *self);
static const char *Catalog_gettext(struct Catalog *self, const char *msgid);
static int Catalog_getindex(struct Catalog *self, const char *msgid);
static BOOL Catalog_load_mo(struct Catalog *self, const char *path);

static const char *getlocale(int category);
static const char *getdefaultlocale();
static const char *getlocalecodeset(const char *locale);
static const char *getcategoryname(int category);
static struct Domain *getdomain(const char *domainname);
static char *readfile(const char *path);
static int readint32(const char *p);
static char *str_iconv(const char *fromcode, const char *tocode, const char *str, size_t len);

static struct Slist *domain_head = NULL;
static struct Domain *cur_domain = NULL;

char *
gettext(const char *msgid)
{
    if (cur_domain == NULL)
        return (char *)msgid;
    return (char *)Domain_cgettext(cur_domain, msgid, LC_MESSAGES);
}

char *
dgettext(const char *domainname, const char *msgid)
{
    struct Domain *d;

    d = getdomain(domainname);
    if (d == NULL)
        return (char *)msgid;
    return (char *)Domain_cgettext(d, msgid, LC_MESSAGES);
}

char *
dcgettext(const char *domainname, const char *msgid, int category)
{
    struct Domain *d;

    d = getdomain(domainname);
    if (d == NULL)
        return (char *)msgid;
    return (char *)Domain_cgettext(d, msgid, category);
}

char *
textdomain(const char *domainname)
{
    struct Domain *d;

    if (domainname == NULL)
        d = cur_domain;
    else
        d = getdomain(domainname);

    if (d == NULL)
        return NULL;

    cur_domain = d;

    return (char *)Domain_get_domainname(cur_domain);
}

char *
bindtextdomain(const char *domainname, const char *dirname)
{
    struct Domain *d;

    d = getdomain(domainname);
    if (d == NULL)
        return NULL;

    if (dirname != NULL)
    {
        if (!Domain_set_dirname(d, dirname))
            return NULL;
    }

    return (char *)Domain_get_dirname(d);
}

char *
bind_textdomain_codeset(const char *domainname, const char *codeset)
{
    struct Domain *d;

    d = getdomain(domainname);
    if (d == NULL)
        return NULL;

    if (codeset != NULL)
    {
        if (!Domain_set_codeset(d, codeset))
            return NULL;
    }

    return (char *)Domain_get_codeset(d);
}

static struct Slist *
Slist_add(struct Slist **phead)
{
    struct Slist *s;

    s = malloc(sizeof(struct Slist));
    if (s == NULL)
        return NULL;

    s->data = NULL;
    s->next = *phead;
    *phead = s;
    return s;
}

static void
Slist_delete(struct Slist **phead, struct Slist *x)
{
    struct Slist *s;
    struct Slist **pn = phead;

    for (s = *phead; s != NULL; s = s->next)
    {
        if (s == x)
        {
            *pn = s->next;
            free(x);
            break;
        }
        pn = &s->next;
    }
}

static struct Domain *
Domain_new()
{
    struct Domain *self;

    self = malloc(sizeof(struct Domain));
    if (self == NULL)
        return NULL;

    self->domainname = NULL;
    self->dirname = NULL;
    self->codeset = NULL;
    self->catalog_head = NULL;

    return self;
}

static void
Domain_delete(struct Domain *self)
{
    if (self->domainname != NULL)
        free(self->domainname);

    if (self->dirname != NULL)
        free(self->dirname);

    if (self->codeset != NULL)
        free(self->codeset);

    while (self->catalog_head != NULL)
    {
        Catalog_delete(self->catalog_head->data);
        Slist_delete(&self->catalog_head, self->catalog_head);
    }

    free(self);
}

static BOOL
Domain_set_domainname(struct Domain *self, const char *domainname)
{
    char *p;

    p = strdup(domainname);
    if (p == NULL)
        return FALSE;

    if (self->domainname != NULL)
        free(self->domainname);

    self->domainname = p;

    return TRUE;
}

static const char *
Domain_get_domainname(struct Domain *self)
{
    return self->domainname;
}

static BOOL
Domain_set_dirname(struct Domain *self, const char *dirname)
{
    char *p;

    p = strdup(dirname);
    if (p == NULL)
        return FALSE;

    if (self->dirname != NULL)
        free(self->dirname);

    self->dirname = p;

    return TRUE;
}

static const char *
Domain_get_dirname(struct Domain *self)
{
    return self->dirname;
}

static BOOL
Domain_set_codeset(struct Domain *self, const char *codeset)
{
    struct Slist *s;
    struct Catalog *c;
    char *p;

    p = strdup(codeset);
    if (p == NULL)
        return FALSE;

    if (self->codeset != NULL)
        free(self->codeset);

    self->codeset = p;

    for (s = self->catalog_head; s != NULL; s = s->next)
    {
        c = (struct Catalog *)s->data;
        if (!Catalog_set_codeset(c, self->codeset))
            return FALSE;   // FIXME: not fail safe
    }

    return TRUE;
}

static const char *
Domain_get_codeset(struct Domain *self)
{
    return self->codeset;
}

static const char *
Domain_cgettext(struct Domain *self, const char *msgid, int category)
{
    struct Catalog *c;

    c = Domain_getcatalog(self, category);
    if (c == NULL)
        return msgid;

    return Catalog_gettext(c, msgid);
}

static struct Catalog *
Domain_getcatalog(struct Domain *self, int category)
{
    struct Slist *s;
    struct Catalog *c;
    const char *locale;
    const char *mopath;

    locale = getlocale(category);
    if (locale == NULL)
        return NULL;

    for (s = self->catalog_head; s != NULL; s = s->next)
    {
        c = (struct Catalog *)s->data;
        if (strcmp(Catalog_get_locale(c), locale) == 0
                && Catalog_get_category(c) == category)
            return c;
    }

    c = Catalog_new();
    if (c == NULL)
        return NULL;

    if (!Catalog_set_locale(c, locale))
    {
        Catalog_delete(c);
        return NULL;
    }

    if (!Catalog_set_category(c, category))
    {
        Catalog_delete(c);
        return NULL;
    }

    if (Domain_get_codeset(self) != NULL)
    {
        if (!Catalog_set_codeset(c, Domain_get_codeset(self)))
        {
            Catalog_delete(c);
            return NULL;
        }
    }

    mopath = Domain_mo_path(self, category, locale);
    if (mopath == NULL)
    {
        Catalog_delete(c);
        return NULL;
    }

    if (!Catalog_load_mo(c, mopath))
    {
        Catalog_delete(c);
        return NULL;
    }

    s = Slist_add(&self->catalog_head);
    if (s == NULL)
    {
        Catalog_delete(c);
        return NULL;
    }

    s->data = c;

    return c;
}

static const char *
Domain_mo_path(struct Domain *self, int category, const char *locale)
{
    const char *dirname;
    const char *categoryname;
    static char buf[1024];

    dirname = Domain_get_dirname(self);
    if (dirname == NULL)
        dirname = DEFAULT_DIRNAME;

    categoryname = getcategoryname(category);
    if (categoryname == NULL)
        return NULL;

    sprintf(buf, "%s\\%s\\%s\\%s.mo", dirname, locale, categoryname, Domain_get_domainname(self));

    return buf;
}

static struct Catalog *
Catalog_new()
{
    struct Catalog *self;

    self = malloc(sizeof(struct Catalog));
    if (self == NULL)
        return NULL;

    self->locale = NULL;
    self->category = 0;
    self->codeset = NULL;
    self->size = 0;
    self->original = NULL;
    self->translation = NULL;
    self->encoded = NULL;
    self->modata = NULL;
    self->mocodeset = NULL;

    return self;
}

static void
Catalog_delete(struct Catalog *self)
{
    int i;

    if (self->locale != NULL)
        free(self->locale);

    if (self->codeset != NULL)
        free(self->codeset);

    if (self->original != NULL)
        free(self->original);

    if (self->translation != NULL)
        free(self->translation);

    if (self->encoded != NULL)
    {
        for (i = 0; i < self->size; ++i)
            if (self->encoded[i] != NULL)
                free(self->encoded[i]);
        free(self->encoded);
    }

    if (self->modata != NULL)
        free(self->modata);

    if (self->mocodeset != NULL)
        free(self->mocodeset);

    free(self);
}

static BOOL
Catalog_set_locale(struct Catalog *self, const char *locale)
{
    char *p;

    p = strdup(locale);
    if (p == NULL)
        return FALSE;

    if (self->locale != NULL)
        free(self->locale);

    self->locale = p;

    return TRUE;
}

static const char *
Catalog_get_locale(struct Catalog *self)
{
    return self->locale;
}

static BOOL
Catalog_set_category(struct Catalog *self, int category)
{
    self->category = category;
    return TRUE;
}

static int
Catalog_get_category(struct Catalog *self)
{
    return self->category;
}

static BOOL
Catalog_set_codeset(struct Catalog *self, const char *codeset)
{
    char *p;
    int i;

    p = strdup(codeset);
    if (p == NULL)
        return FALSE;

    if (self->codeset != NULL)
        free(self->codeset);

    self->codeset = p;

    if (self->encoded != NULL)
    {
        for (i = 0; i < self->size; ++i)
        {
            if (self->encoded[i] != NULL)
            {
                free(self->encoded[i]);
                self->encoded[i] = NULL;
            }
        }
    }

    return TRUE;
}

static const char *
Catalog_get_codeset(struct Catalog *self)
{
    return self->codeset;
}

static const char *
Catalog_gettext(struct Catalog *self, const char *msgid)
{
    int i;
    char outenc[32];
    char moenc[32];
    char *p;
    const char *t;
    const char *loc;

    i = Catalog_getindex(self, msgid);
    if (i == -1)
        return msgid;

    if (self->encoded[i] != NULL)
        return self->encoded[i];

    t = Catalog_get_codeset(self);
    if (t == NULL)
    {
        loc = getdefaultlocale();
        if (loc != NULL)
            t = getlocalecodeset(loc);
    }
    if (t == NULL)
        return self->translation[i];
    strcpy(outenc, t);

    t = self->mocodeset;
    if (t == NULL)
        t = getlocalecodeset(Catalog_get_locale(self));
    if (t == NULL)
        return self->translation[i];
    strcpy(moenc, t);

    p = str_iconv(moenc, outenc, self->translation[i], -1);
    if (p == NULL)
        return self->translation[i];

    self->encoded[i] = p;

    return self->encoded[i];
}

static int
Catalog_getindex(struct Catalog *self, const char *msgid)
{
    int left;
    int right;
    int mid;
    int c;

    left = 0;
    right = self->size;
    while (left < right)
    {
        mid = (left + right) / 2;
        c = strcmp(self->original[mid], msgid);
        if (c == 0)
            return mid;
        else if (c < 0)
            left = mid + 1;
        else
            right = mid;
    }

    return -1;
}

static BOOL
Catalog_load_mo(struct Catalog *self, const char *path)
{
    int N;
    int O;
    int T;
    int i;
    int off;
    char *p;
    size_t len;

    self->modata = readfile(path);
    if (self->modata == NULL)
        return FALSE;

    if (readint32(self->modata) != 0x950412de)
        return FALSE;

    if (readint32(&self->modata[4]) != 0)
        return FALSE;

    N = readint32(&self->modata[8]);
    O = readint32(&self->modata[12]);
    T = readint32(&self->modata[16]);

    self->size = N;

    self->original = malloc(sizeof(const char *) * N);
    if (self->original == NULL)
        return FALSE;

    for (i = 0; i < N; ++i)
    {
        off = readint32(&self->modata[O + i * 8 + 4]);
        self->original[i] = &self->modata[off];
    }

    self->translation = malloc(sizeof(const char *) * N);
    if (self->translation == NULL)
        return FALSE;

    for (i = 0; i < N; ++i)
    {
        off = readint32(&self->modata[T + i * 8 + 4]);
        self->translation[i] = &self->modata[off];
    }

    self->encoded = malloc(sizeof(const char *) * N);
    if (self->encoded == NULL)
        return FALSE;

    for (i = 0; i < N; ++i)
        self->encoded[i] = NULL;

    // FIXME: specification?
    i = Catalog_getindex(self, "");
    if (i != -1)
    {
        p = strstr(self->translation[i], "charset=");
        if (p != NULL)
        {
            p = p + strlen("charset=");
            len = strcspn(p, " \t\n");
            self->mocodeset = malloc(len + 1);
            if (self->mocodeset == NULL)
                return FALSE;
            memmove(self->mocodeset, p, len);
            self->mocodeset[len] = '\0';
        }
    }

    return TRUE;
}

// FIXME: how to get gettext compatible behavior?
static const char *
getlocale(int category)
{
    if (category == LC_MESSAGES)
    {
        static char buf[1024];
        if (GetEnvironmentVariable("LC_MESSAGES", buf, sizeof(buf)) != 0)
            return buf;
        if (GetEnvironmentVariable("LANG", buf, sizeof(buf)) != 0)
            return buf;
        return getdefaultlocale();
    }
    return setlocale(category, NULL);
}

// FIXME:
static const char *
getdefaultlocale()
{
    wchar_t wname[32];
    static char name[32];

    if (GetUserDefaultLocaleName(wname, 32) == 0)
        return NULL;

    if (wcstombs(name, wname, wcslen(wname) + 1) == -1)
        return NULL;

    return name;
}

static const char *
getlocalecodeset(const char *locale)
{
    wchar_t wlocale[128];
    wchar_t wcodeset[32];
    static char codeset[32];
    char *p;

    if (mbstowcs(wlocale, locale, strlen(locale) + 1) == -1)
        return NULL;

    if (GetLocaleInfoEx(wlocale, LOCALE_IDEFAULTCODEPAGE, wcodeset, 32) != 0)
    {
        if (wcstombs(codeset, wcodeset, wcslen(wcodeset) + 1) == -1)
            return NULL;
        return codeset;
    }

    // Get codeset from Japanese_Japan.932 form.
    p = strchr(locale, '.');
    if (p != NULL)
    {
        strcpy(codeset, p + 1);
        return codeset;
    }

    return NULL;
}

static const char *
getcategoryname(int category)
{
    switch (category) {
    case LC_ALL:
        return "LC_ALL";
    case LC_COLLATE:
        return "LC_COLLATE";
    case LC_CTYPE:
        return "LC_CTYPE";
    case LC_MONETARY:
        return "LC_MONETARY";
    case LC_NUMERIC:
        return "LC_NUMERIC";
    case LC_TIME:
        return "LC_TIME";
    case LC_MESSAGES:
        return "LC_MESSAGES";
    default:
        return NULL;
    }
}

static struct Domain *
getdomain(const char *domainname)
{
    struct Slist *s;
    struct Domain *d;

    for (s = domain_head; s != NULL; s = s->next)
    {
        d = (struct Domain *)s->data;
        if (strcmp(Domain_get_domainname(d), domainname) == 0)
            return d;
    }

    d = Domain_new();
    if (d == NULL)
        return NULL;

    if (!Domain_set_domainname(d, domainname))
    {
        Domain_delete(d);
        return NULL;
    }

    s = Slist_add(&domain_head);
    if (s == NULL)
    {
        Domain_delete(d);
        return NULL;
    }

    s->data = d;

    return d;
}

static char *
readfile(const char *path)
{
    FILE *f;
    long fsize;
    char *p;

    f = fopen(path, "rb");
    if (f == NULL)
        return FALSE;

    if (fseek(f, 0, SEEK_END) == -1)
    {
        fclose(f);
        return NULL;
    }

    fsize = ftell(f);

    if (fseek(f, 0, SEEK_SET) == -1)
    {
        fclose(f);
        return NULL;
    }

    p = malloc(fsize);
    if (p == NULL)
    {
        fclose(f);
        return NULL;
    }

    if (fread(p, 1, fsize, f) != fsize)
    {
        fclose(f);
        free(p);
        return NULL;
    }

    return p;
}

static int
readint32(const char *p)
{
    return (unsigned char)p[0]
        + ((unsigned char)p[1] << 8)
        + ((unsigned char)p[2] << 16)
        + ((unsigned char)p[3] << 24);
}

static char *
str_iconv(const char *fromcode, const char *tocode, const char *str, size_t len)
{
    iconv_t cd = (iconv_t)(-1);
    char buf[8192];
    char *outbuf = NULL;
    size_t outlen;
    char *newbuf;
    const char *from;
    size_t fromlen;
    char *to;
    size_t tolen;
    size_t r;

    cd = iconv_open(tocode, fromcode);
    if (cd == (iconv_t)(-1))
        return NULL;

    from = str;
    if (len == (size_t)(-1))
        fromlen = strlen(str);
    else
        fromlen = len;

    outlen = 1;
    outbuf = calloc(outlen, sizeof(char));
    if (outbuf == NULL)
        goto onerror;

    while (fromlen > 0) {
        to = buf;
        tolen = sizeof(buf);
        r = iconv(cd, (void *)&from, &fromlen, &to, &tolen);
        if (r == (size_t)(-1)) {
            if (errno == E2BIG) {
                /* There is not sufficient room at *outbuf. */
                /* Verbose check. */
                if (to == buf)
                    goto onerror;
            } else if (errno == EILSEQ) {
                /* An invalid multibyte sequence has been encountered in
                 * the input. */
                goto onerror;
            } else if (errno == EINVAL) {
                /* An incomplete multibyte sequence has been encountered
                 * in the input. */
                /* Read more bytes from input if possible. */
                goto onerror;
            } else {
                /* Unknown error.  Probarly never happen. */
                goto onerror;
            }
        }
        newbuf = realloc(outbuf, outlen + (to - buf));
        if (newbuf == NULL)
            goto onerror;
        outbuf = newbuf;
        memmove(outbuf + outlen - 1, buf, to - buf);
        outlen = outlen + (to - buf);
        outbuf[outlen - 1] = '\0';
    }

    /* flush */
    to = buf;
    tolen = sizeof(buf);
    r = iconv(cd, NULL, NULL, &to, &tolen);
    if (r == (size_t)(-1))
        goto onerror;
    if (to - buf > 0) {
        newbuf = realloc(outbuf, outlen + (to - buf));
        if (newbuf == NULL)
            goto onerror;
        outbuf = newbuf;
        memmove(outbuf + outlen - 1, buf, to - buf);
        outlen = outlen + (to - buf);
        outbuf[outlen - 1] = '\0';
    }

    iconv_close(cd);

    return outbuf;

onerror:
    if (outbuf != NULL)
        free(outbuf);
    if (cd != (iconv_t)(-1))
        iconv_close(cd);
    return NULL;
}

