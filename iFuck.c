#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <curl/curl.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#ifndef USERNAME
#define USERNAME "admin"
#endif
#ifndef PASSWORD
#define PASSWORD "admin"
#endif
static volatile int running = 1;

void int_handler(int sig) {
    (void)sig;
    running = 0;
}

char *md5_hex(const char *s) {
    EVP_MD_CTX *mdctx;
    unsigned char d[EVP_MD_size(EVP_md5())];
    unsigned int len;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
    EVP_DigestUpdate(mdctx, s, strlen(s));
    EVP_DigestFinal_ex(mdctx, d, &len);
    EVP_MD_CTX_free(mdctx);
    char *out = malloc(2 * len + 1);
    for(int i = 0; i < len; i++)
        sprintf(out + 2*i, "%02x", d[i]);
    out[2 * len] = 0;
    return out;
}

char *b64(const char *in) {
    int len = strlen(in);
    int outlen = 4 * ((len + 2) / 3);
    char *out = malloc(outlen + 1);
    EVP_EncodeBlock((unsigned char*)out, (unsigned char*)in, len);
    out[outlen] = 0;
    return out;
}

struct hdr {
    char *sess;
};

size_t header_cb(char *buffer, size_t size, size_t nitems, void *userdata) {
    size_t len = size * nitems;
    struct hdr *h = userdata;
    const char *p = "Set-Cookie:";

    if(len > 11 && strncasecmp(buffer, p, 11) == 0) {
        char *s = strstr(buffer, "sess_key=");
        if(s) {
            s += 9;
            char *e = strchr(s, ';');
            size_t l = e ? (size_t)(e - s) : strlen(s);
            free(h->sess);
            h->sess = malloc(l + 1);
            memcpy(h->sess, s, l);
            h->sess[l] = 0;
        }
    }
    return len;
}

char *do_login(CURL *c) {
    struct hdr h = {0};
    struct curl_slist *hs = NULL;
    CURLcode res;
    char *md5 = md5_hex(PASSWORD);
    char *b = b64(PASSWORD);
    char *pass = malloc(6 + strlen(b) + 1);
    strcpy(pass, "salt_11");
    strcat(pass, b);
    char payload[256];
    snprintf(payload, sizeof(payload),
             "{\"username\":\"%s\",\"passwd\":\"%s\",\"pass\":\"%s\",\"remember_password\":\"false\"}",
             USERNAME, md5, pass);
    hs = curl_slist_append(hs, "Accept: application/json, text/plain, */*");
    hs = curl_slist_append(hs, "Accept-Encoding: gzip, deflate");
    hs = curl_slist_append(hs, "Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7");
    hs = curl_slist_append(hs, "Connection: keep-alive");
    hs = curl_slist_append(hs, "Content-Type: application/json;charset=UTF-8");
    char cookie_hdr[128];
    snprintf(cookie_hdr, sizeof(cookie_hdr), "Cookie: username=%s", USERNAME);
    hs = curl_slist_append(hs, cookie_hdr);
    curl_easy_setopt(c, CURLOPT_URL, "http://192.168.9.1/Action/login");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(c, CURLOPT_HEADERDATA, &h);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    res = curl_easy_perform(c);
    curl_slist_free_all(hs);
    free(md5);
    free(b);
    free(pass);
    if(res != CURLE_OK) {
        free(h.sess);
        return NULL;
    }
    return h.sess;
}

void do_call(CURL *c, const char *sess) {
    struct curl_slist *hs = NULL;
    hs = curl_slist_append(hs, "Accept: application/json, text/plain, */*");
    hs = curl_slist_append(hs, "Accept-Encoding: gzip, deflate");
    hs = curl_slist_append(hs, "Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7");
    hs = curl_slist_append(hs, "Connection: keep-alive");
    hs = curl_slist_append(hs, "Content-Type: application/json;charset=UTF-8");
    char cookie_hdr[256];
    snprintf(cookie_hdr, sizeof(cookie_hdr),
             "Cookie: sess_key=%s; username=%s; login=1", sess, USERNAME);
    hs = curl_slist_append(hs, cookie_hdr);
    long fixed_timestamp = 1420070400L;
    char payload[128];
    snprintf(payload, sizeof(payload),
             "{\"func_name\":\"basic\",\"action\":\"set_time\",\"param\":{\"timestamp\":%ld}}",
             fixed_timestamp);
    curl_easy_setopt(c, CURLOPT_URL, "http://192.168.9.1/Action/call");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(c);
    curl_slist_free_all(hs);
}

void do_logout(CURL *c, const char *sess) {
    struct curl_slist *hs = NULL;
    hs = curl_slist_append(hs, "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
    hs = curl_slist_append(hs, "Accept-Encoding: gzip, deflate");
    hs = curl_slist_append(hs, "Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7");
    hs = curl_slist_append(hs, "Connection: keep-alive");
    char cookie_hdr[256];
    snprintf(cookie_hdr, sizeof(cookie_hdr),
             "Cookie: sess_key=%s; username=%s", sess, USERNAME);
    hs = curl_slist_append(hs, cookie_hdr);
    curl_easy_setopt(c, CURLOPT_URL, "http://192.168.9.1/Action/logout");
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);
    curl_easy_setopt(c, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    curl_easy_perform(c);
    curl_slist_free_all(hs);
}

int main() {
    signal(SIGINT, int_handler);
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *c = curl_easy_init();
    if(!c) return 1;
    while(running) {
        char *sess = NULL;
        while(running) {
            sess = do_login(c);
            if(sess && strlen(sess)) {
                printf("Login Successful, sess_key: %s\n", sess);
                break;
            }
            fprintf(stderr, "Login failed, retrying in 10 seconds\n");
            for(int i = 0; i < 10 && running; i++) sleep(1);
        }
        if(!running || !sess) break;
        printf("Modification time set to 2015-01-01 08:00:00 UTC...\n");
        do_call(c, sess);
        printf("logout...\n");
        do_logout(c, sess);
        free(sess);
        printf("wait...\n");
        for(int i = 0; i < 60 && running; i++) sleep(1);
    }
    curl_easy_cleanup(c);
    curl_global_cleanup();
    return 0;
}
