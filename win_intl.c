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

#include "win_iconv.c"

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
    const char *domainname;
    const char *dirname;
    const char *codeset;
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
static const char *Domain_mo_path(struct Domain *self, int category);

struct Catalog {
    const char *locale;
    int category;
    const char *codeset;
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
static char *convert_string(const char *s, const char *fromenc, const char *toenc);
static char *str_iconv(const char *fromcode, const char *tocode, const char *str, size_t len);
static char *lcid_to_name(LCID lcid);

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

    s = (struct Slist *)malloc(sizeof(struct Slist));
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
            free((void *)x);
            break;
        }
        pn = &s->next;
    }
}

static struct Domain *
Domain_new()
{
    struct Domain *self;

    self = (struct Domain *)malloc(sizeof(struct Domain));
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
        free((void *)self->domainname);

    if (self->dirname != NULL)
        free((void *)self->dirname);

    if (self->codeset != NULL)
        free((void *)self->codeset);

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
    const char *p;

    p = strdup(domainname);
    if (p == NULL)
        return FALSE;

    if (self->domainname != NULL)
        free((void *)self->domainname);

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
    const char *p;

    p = strdup(dirname);
    if (p == NULL)
        return FALSE;

    if (self->dirname != NULL)
        free((void *)self->dirname);

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
    const char *p;

    p = strdup(codeset);
    if (p == NULL)
        return FALSE;

    if (self->codeset != NULL)
        free((void *)self->codeset);

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

    mopath = Domain_mo_path(self, category);
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
Domain_mo_path(struct Domain *self, int category)
{
    const char *dirname;
    const char *locale;
    const char *categoryname;
    static char buf[1024];

    dirname = Domain_get_dirname(self);
    if (dirname == NULL)
        dirname = DEFAULT_DIRNAME;

    locale = getlocale(category);
    if (locale == NULL)
        return NULL;

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

    self = (struct Catalog *)malloc(sizeof(struct Catalog));
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
        free((void *)self->locale);

    if (self->codeset != NULL)
        free((void *)self->codeset);

    if (self->original != NULL)
        free((void *)self->original);

    if (self->translation != NULL)
        free((void *)self->translation);

    if (self->encoded != NULL)
    {
        for (i = 0; i < self->size; ++i)
            if (self->encoded[i] != NULL)
                free((void *)self->encoded[i]);
        free((void *)self->encoded);
    }

    if (self->modata != NULL)
        free((void *)self->modata);

    if (self->mocodeset != NULL)
        free((void *)self->mocodeset);

    free((void *)self);
}

static BOOL
Catalog_set_locale(struct Catalog *self, const char *locale)
{
    const char *p;

    p = strdup(locale);
    if (p == NULL)
        return FALSE;

    if (self->locale != NULL)
        free((void *)self->locale);

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
    const char *p;
    int i;

    p = strdup(codeset);
    if (p == NULL)
        return FALSE;

    self->codeset = p;

    if (self->encoded != NULL)
    {
        for (i = 0; i < self->size; ++i)
        {
            if (self->encoded[i] != NULL)
                free((void *)self->encoded[i]);
            self->encoded[i] = NULL;
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
    const char *moenc;
    char *p;

    i = Catalog_getindex(self, msgid);
    if (i == -1)
        return msgid;

    if (Catalog_get_codeset(self) == NULL)
        return self->translation[i];

    if (self->encoded[i] != NULL)
        return self->encoded[i];

    moenc = self->mocodeset;
    if (moenc == NULL)
        moenc = getlocalecodeset(Catalog_get_locale(self));

    if (moenc == NULL)
        return self->translation[i];

    p = str_iconv(moenc, Catalog_get_codeset(self), self->translation[i], -1);
    if (p == NULL)
        return self->translation[i];

    self->encoded[i] = p;

    return self->encoded[i];
}

static int
Catalog_getindex(struct Catalog *self, const char *msgid)
{
    // FIXME: binary search
    int i;

    for (i = 0; i < self->size; ++i)
        if (strcmp(self->original[i], msgid) == 0)
            return i;
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

    self->original = (char **)malloc(sizeof(const char *) * N);
    if (self->original == NULL)
        return FALSE;

    for (i = 0; i < N; ++i)
    {
        off = readint32(&self->modata[O + i * 8 + 4]);
        self->original[i] = &self->modata[off];
    }

    self->translation = (char **)malloc(sizeof(const char *) * N);
    if (self->translation == NULL)
        return FALSE;

    for (i = 0; i < N; ++i)
    {
        off = readint32(&self->modata[T + i * 8 + 4]);
        self->translation[i] = &self->modata[off];
    }

    self->encoded = (char **)malloc(sizeof(const char *) * N);
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
            self->mocodeset = (char *)malloc(len + 1);
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
        return getdefaultlocale();
    }
    return setlocale(category, NULL);
}

// FIXME:
static const char *
getdefaultlocale()
{
    LANGID lcid;
    char *p;
    wchar_t wname[32];
    static char name[32];

    lcid = GetUserDefaultUILanguage();

    p = lcid_to_name(lcid);
    if (p != NULL)
        return p;

    if (LCIDToLocaleName(lcid, wname, 32, 0) == 0)
        return NULL;

    if (wcstombs(name, wname, wcslen(wname) + 1) == -1)
        return NULL;

    return name;
}

// FIXME: Name (Japanese_Japan.932) returned by setlocale() doesn't work.
static const char *
getlocalecodeset(const char *locale)
{
    wchar_t wlocale[128];
    wchar_t wcodeset[32];
    static char codeset[32];

    if (mbstowcs(wlocale, locale, strlen(locale) + 1) == -1)
        return NULL;

    if (GetLocaleInfoEx(wlocale, LOCALE_IDEFAULTCODEPAGE, wcodeset, 32) == 0)
        return NULL;

    if (wcstombs(codeset, wcodeset, wcslen(wcodeset) + 1) == -1)
        return NULL;

    return codeset;
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
        free((void *)p);
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
        free((void *)outbuf);
    if (cd != (iconv_t)(-1))
        iconv_close(cd);
    return NULL;
}

// WORKAROUND:
// list is from // https://msdn.microsoft.com/library/cc392381.aspx
struct LCIDName {
    LCID lcid;
    const char *name;
} LCIDNames[] = {
    {0x0436, "af"},
    {0x0439, "hi"},
    {0x041C, "sq"},
    {0x040E, "hu"},
    {0x3801, "ar-ae"},
    {0x040F, "is"},
    {0x3C01, "ar-bh"},
    {0x0421, "in"},
    {0x1401, "ar-dz"},
    {0x0410, "it"},
    {0x0C01, "ar-eg"},
    {0x0810, "it-ch"},
    {0x0801, "ar-iq"},
    {0x0411, "ja"},
    {0x2C01, "ar-jo"},
    {0x0412, "ko"},
    {0x3401, "ar-kw"},
    {0x0426, "lv"},
    {0x3001, "ar-lb"},
    {0x0427, "lt"},
    {0x1001, "ar-ly"},
    {0x042F, "mk"},
    {0x1801, "ar-ma"},
    {0x043E, "ms"},
    {0x2001, "ar-om"},
    {0x043A, "mt"},
    {0x4001, "ar-qa"},
    {0x0414, "no"},
    {0x0401, "ar-sa"},
    {0x0415, "pl"},
    {0x2801, "ar-sy"},
    {0x0816, "pt"},
    {0x1C01, "ar-tn"},
    {0x0416, "pt-br"},
    {0x2401, "ar-ye"},
    {0x0417, "rm"},
    {0x042D, "eu"},
    {0x0418, "ro"},
    {0x0423, "be"},
    {0x0818, "ro-mo"},
    {0x0402, "bg"},
    {0x0419, "ru"},
    {0x0403, "ca"},
    {0x0819, "ru-mo"},
    {0x0804, "zh-cn"},
    {0x0C1A, "sr"},
    {0x0C04, "zh-hk"},
    {0x0432, "tn"},
    {0x1004, "zh-sg"},
    {0x0424, "sl"},
    {0x0404, "zh-tw"},
    {0x041B, "sk"},
    {0x041A, "hr"},
    {0x042E, "sb"},
    {0x0405, "cs"},
    {0x040A, "es"},
    {0x0406, "da"},
    {0x2C0A, "es-ar"},
    {0x0413, "nl"},
    {0x400A, "es-bo"},
    {0x0813, "nl-be"},
    {0x340A, "es-cl"},
    {0x0C09, "en-au"},
    {0x240A, "es-co"},
    {0x2809, "en-bz"},
    {0x140A, "es-cr"},
    {0x1009, "en-ca"},
    {0x1C0A, "es-do"},
    {0x1809, "en-ie"},
    {0x300A, "es-ec"},
    {0x2009, "en-jm"},
    {0x100A, "es-gt"},
    {0x1409, "en-nz"},
    {0x480A, "es-hn"},
    {0x1C09, "en-za"},
    {0x080A, "es-mx"},
    {0x2C09, "en-tt"},
    {0x4C0A, "es-ni"},
    {0x0809, "en-gb"},
    {0x180A, "es-pa"},
    {0x0409, "en-us"},
    {0x280A, "es-pe"},
    {0x0425, "et"},
    {0x500A, "es-pr"},
    {0x0429, "fa"},
    {0x3C0A, "es-py"},
    {0x040B, "fi"},
    {0x440A, "es-sv"},
    {0x0438, "fo"},
    {0x380A, "es-uy"},
    {0x040C, "fr"},
    {0x200A, "es-ve"},
    {0x080C, "fr-be"},
    {0x0430, "sx"},
    {0x0C0C, "fr-ca"},
    {0x041D, "sv"},
    {0x140C, "fr-lu"},
    {0x081D, "sv-fi"},
    {0x100C, "fr-ch"},
    {0x041E, "th"},
    {0x043C, "gd"},
    {0x041F, "tr"},
    {0x0407, "de"},
    {0x0431, "ts"},
    {0x0C07, "de-at"},
    {0x0422, "uk"},
    {0x1407, "de-li"},
    {0x0420, "ur"},
    {0x1007, "de-lu"},
    {0x042A, "vi"},
    {0x0807, "de-ch"},
    {0x0434, "xh"},
    {0x0408, "el"},
    {0x043D, "ji"},
    {0x040D, "he"},
    {0x0435, "zu"},
    {0, NULL}
};

static char *
lcid_to_name(LCID lcid)
{
    int i;

    for (i = 0; LCIDNames[i].lcid != 0; ++i)
        if (LCIDNames[i].lcid == lcid)
            return LCIDNames[i].name;
    return NULL;
}

