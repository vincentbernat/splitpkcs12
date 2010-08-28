/* Copyright (c) 2010 Vincent Bernat <bernat@luffy.cx>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
*/

/* Simple program to split a given PKCS#12 certificate into three
   components:
     - user certificate
     - user private key
     - other certificates (including CA certificate)

   This program should be run with the PKCS#12 certificate as first
   argument. It will ask the password if necessary. The three
   components are written in the same directory than the original
   certificate using the following names:
     - user.pem
     - user.key
     - certs.pem
*/

#include <stdio.h>
#include <unistd.h>
#if defined(WIN32)
# include <windows.h>
#else
# include <termios.h>
#endif
#include <string.h>
#include <libgen.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#if defined(WIN32)
# include <openssl/applink.c>
#endif

/* Ask for a password using `prompt' as a prompt and store the result
   in `buffer' which is allocated by the function. Return 0 on
   success, -1 on error. */
int
getpassword(const char *prompt, char **buffer) {
#if defined(WIN32)
  HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
  HANDLE hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD mode, nb;
#else
  struct termios tty;
  tcflag_t c_lflag;
#endif
  int i, c, buflen;

  if (!buffer) {
    return -1;
  }

  /* Initialize buffer */
  buflen = 10;
  *buffer = malloc(buflen);
  if (!buffer)
    return -1;

  /* Prompt + terminal initialization */
#if defined(WIN32)
  if ((hstdin == INVALID_HANDLE_VALUE) ||
      (hstdout == INVALID_HANDLE_VALUE)) {
    fprintf(stderr, "[!] Unable to access console\n");
    return -1;
  }
  WriteConsole(hstdout, prompt, strlen(prompt), &nb, NULL);
  if (!GetConsoleMode(hstdin, &mode))
    return -1;

  if (!SetConsoleMode(hstdin,
		      mode & ENABLE_PROCESSED_INPUT & ~ENABLE_ECHO_INPUT))
      return -1;
#else
  fprintf(stderr, "%s", prompt);
  if (tcgetattr(STDIN_FILENO, &tty) < 0)
    return -1;
  c_lflag = tty.c_lflag;
  tty.c_lflag &= ~(ICANON | ECHO);
  if (tcsetattr(STDIN_FILENO, 0, &tty) < 0)
    return -1;
#endif

  /* Read the password */
  i = c = 0;
  while (1) {
#if defined(WIN32)
    if (!ReadConsole(hstdin, &c, 1, &nb, NULL))
      break;
#else
    c = getchar();
#endif
    if ((c == EOF) || (c == '\n') || (c == '\r'))
      break;
    if (i >= buflen) {
      buflen *= 2;
      if (!realloc(*buffer, buflen)) {
	free(buffer); buffer = NULL;
	break;
      }
    }
#if defined(WIN32)
    WriteConsole(hstdout, "*", 1, &nb, NULL);
#else
    putchar('*');
#endif
    (*buffer)[i] = c;
    i++;
  }
  (*buffer)[i] = '\0';
#if defined(WIN32)
  WriteConsole(hstdout, "\n", 1, &nb, NULL);
  SetConsoleMode(hstdin, mode);
#else
  putchar('\n');
  tty.c_lflag = c_lflag;
  tcsetattr(STDIN_FILENO, 0, &tty);
#endif
  return (buffer == NULL)?-1:0;
}

int
main(int argc, char **argv) {
  FILE           *fp   = NULL;
  EVP_PKEY       *pkey = NULL;
  X509           *cert = NULL;
  STACK_OF(X509) *ca   = NULL;
  PKCS12         *p12  = NULL;

  char *pass = strdup("");
  int  i;

  if (argc != 2) {
    fprintf(stderr, "[!] Usage: %s certificate.p12\n", argv[0]);
    exit(1);
  }

  printf("[+] Initializing OpenSSL\n");
  SSLeay_add_all_algorithms();
  ERR_load_crypto_strings();

  printf("[+] Opening PKCS#12 certificate\n");
  if (!(fp = fopen(argv[1], "r"))) {
    fprintf(stderr, "[!] Unable to open certificate `%s'\n", argv[1]);
    goto endpkcs12;
  }

  if (chdir(dirname(argv[1])) == -1) {
    fprintf(stderr, "[!] Unable to change directory to `%s'\n",
	    dirname(argv[1]));
    goto endpkcs12;
  }
  p12 = d2i_PKCS12_fp(fp, NULL);
  fclose(fp); fp = NULL;
  if (!p12) {
    fprintf(stderr, "[!] Unable to parse PKCS#12 certificate: %s\n",
	    ERR_reason_error_string(ERR_get_error()));
    goto endpkcs12;
  }
  while (!PKCS12_parse(p12, pass, &pkey, &cert, &ca)) {
    ca = NULL;
    free(pass);
    if (getpassword("[?] Password: ", &pass) == -1)
      goto endpkcs12;
    if (strlen(pass) == 0)
      goto endpkcs12;
  }
  free(pass);
  PKCS12_free(p12); p12 = NULL;
  if (!ca || !sk_num(ca) || !pkey || !cert) {
    fprintf(stderr, "[!] PKCS#12 certificate is incomplete\n");
    goto endpkcs12;
  }

#define PEM_w(path, call) \
  do {									\
    if (!(fp = fopen(path, "w"))) {					\
      fprintf(stderr, "[!] Unable to open `%s'\n", path);		\
      goto endpkcs12;							\
    }									\
    printf("[+] Write certificate to `%s'\n", path);			\
    call;								\
    fclose(fp); fp = NULL;						\
  } while(0)
    
  PEM_w("user.pem", PEM_write_X509(fp, cert));
  PEM_w("user.key",  PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL));
  PEM_w("cacert.pem",
	for (i = 0; i < sk_X509_num(ca); i++)
	  PEM_write_X509(fp, sk_X509_value(ca, i)));
  sk_free(ca); X509_free(cert); EVP_PKEY_free(pkey);
  exit(0);

 endpkcs12:
  if (pass) free(pass);
  if (ca) sk_free(ca);
  if (cert) X509_free(cert);
  if (pkey) EVP_PKEY_free(pkey);
  if (p12) PKCS12_free(p12);
  if (fp) fclose(fp);
  exit(1);
}
