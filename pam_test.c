#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {
    pam_handle_t *pamh = NULL;
    int ret;
    const char *user = "nobody";

    if(argc > 1)
        user = argv[1];

    ret = pam_start("ukey-auth", user, &conv, &pamh);
    
    if (ret == PAM_SUCCESS) {
        ret = pam_authenticate(pamh, 0);
    }

    if (ret == PAM_SUCCESS) {
        printf("认证成功!\n");
    } else {
        printf("认证失败: %s\n", pam_strerror(pamh, ret));
    }

    if (pam_end(pamh, ret) != PAM_SUCCESS) {
        pamh = NULL;
        printf("failed to release authenticator\n");
        exit(1);
    }

    return ret == PAM_SUCCESS ? 0 : 1;
} 