/**
 * TODO:
 *  - finish implementing handlers
 *
 *  - implement set_registers to support breakpoints
 *  - base64 encode argv in get_commandline
 *  - print next instruction on p, t, and g
 *
 *
 *  - Check for allocation errors on json_* functions
 *  - python code check status retval in properties
 *  - remove -g from Makefile
 *
 *  - add support for signals in the child process
 *  - set_bytes (eb, ew, ed commands)
 *  - set_registers (r @eax=<val> commands)
 */
#include <b64/cdecode.h>
#include <b64/cencode.h>
#include <jansson.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEFAULT_BIND_IP     "localhost"
#define DEFAULT_BIND_PORT   "4242"

#define UNREFERENCED_PARAMETER(p)   ((void)(p))
#define min(a,b)    (((a) < (b)) ? (a) : (b))

enum {
    CMD_GET_COMMANDLINE = 1,
    CMD_GET_MODULES,
    CMD_GET_REGISTERS,
    CMD_GET_BYTES,
    CMD_SET_BYTES,
    CMD_GO,
    CMD_STEP_INSTRUCTION,
} cmd_t;


/**
 * @brief Encode a string as base64.
 * @param buffer Data to encode.
 * @param buffer_size Size of the buffer to encode in bytes.
 * @param output_size Size of the encoded buffer in bytes.
 * @return A dynamically allocated buffer with the encoded data or NULL on
 *         error. This buffer should be freed with `free` by the caller.
 */
char * base64_encode(const char *buffer, size_t buffer_size, size_t *output_size)
{
    char *buffer_b64 = NULL;
    size_t b64_size = 0;
    base64_encodestate ctx = {0};
    size_t cnt = 0;

    // base64 encoding requires an output buffer of 4*(n/3) bytes rounded up to
    // a multiple of 4. Add 8 to simplify the rounding and ensure space for a
    // newline and NULL terminator.
    b64_size = 4 * (buffer_size / 3) + 8;
    buffer_b64 = calloc(1, b64_size);
    if (buffer_b64 == NULL) {
        return NULL;
    }

    // base64 encode the data
    base64_init_encodestate(&ctx);
    cnt = base64_encode_block(buffer, buffer_size, buffer_b64, &ctx);
    cnt += base64_encode_blockend(buffer_b64 + cnt, &ctx);

    *output_size = cnt;
    return buffer_b64;
}


/**
 * @brief Decode a base64 string.
 * @param buffer A base64 encoded buffer.
 * @param buffer_size Size of the encoded buffer in bytes.
 * @param output_size Size of the decoded buffer in bytes.
 * @return A dynamically allocated buffer with the decoded data or NULL on
 *         error. This buffer should be freed with `free` by the caller.
 */
char * base64_decode(const char *buffer, size_t buffer_size, size_t *output_size)
{
    char *buffer_str = NULL;
    size_t str_size = 0;
    base64_decodestate ctx = {0};
    size_t cnt = 0;

    // lazily use a buffer the same size as the input one for decoding.
    str_size = buffer_size;
    buffer_str = calloc(1, str_size);
    if (buffer_str == NULL) {
        return NULL;
    }

    // base64 decode the data
    base64_init_decodestate(&ctx);
    cnt = base64_decode_block(buffer, buffer_size, buffer_str, &ctx);

    *output_size = cnt;
    return buffer_str;
}


/**
 * @brief Helper function to send a json blob prefixed with the length.
 * @param sfd Socket fd to send on.
 * @param root JSON root object or array.
 */
static void send_json(int sfd, json_t *root)
{
    char *json = NULL;
    uint32_t len = 0;
    uint32_t len_be = 0;

    json = json_dumps(root, JSON_INDENT(2));
    len = strlen(json);
    len_be = htonl(len);

    (void)send(sfd, &len_be, sizeof(len_be), 0);
    (void)send(sfd, json, len, 0);

    free(json);
}


/**
 * @brief Helper function to recv a json blob prefixed with the length.
 * @param sfd Socket fd to recv from.
 * @return A pointer to the root JSON object or array.
 */
static json_t * recv_json(int sfd)
{
    uint32_t msg_len = 0;
    size_t total_recv = 0;
    ssize_t nrecv = 0;
    json_t *json = NULL;
    json_error_t json_error = {0};

    if (recv(sfd, &msg_len, sizeof(msg_len), 0) != sizeof(msg_len)) {
        return NULL;
    }
    msg_len = ntohl(msg_len);

    char *buffer = calloc(msg_len + 1, 1);
    if (buffer == NULL) {
        return NULL;
    }

    while (total_recv < msg_len) {
        nrecv = recv(sfd, buffer + total_recv, msg_len - total_recv, 0);
        if (nrecv <= 0) {
            free(buffer);
            return NULL;
        }
        total_recv += nrecv;
    }

    json = json_loads(buffer, 0, &json_error);
    free(buffer);
    return json;
}


/**
 * @brief Send a JSON object with a single "status" value.
 */
static void send_status(int sfd, int status)
{
    json_t *root = json_object();
    json_object_set_new(root, "status", json_integer(status));
    send_json(sfd, root);
    json_decref(root);
}


static void handle_get_commandline(int sfd, pid_t pid, json_t *json)
{
    char fname[64] = {0};
    FILE *fp = NULL;
    size_t nread = 0;
    char cmdline[2048] = {0};
    json_t *root = NULL;

    UNREFERENCED_PARAMETER(json);

    snprintf(fname, sizeof(fname), "/proc/%d/cmdline", pid);
    fp = fopen(fname, "r");
    if (fp == NULL) {
        perror("fopen");
        send_status(sfd, errno);
        return;
    }

    nread = fread(cmdline, 1, sizeof(cmdline), fp);
    fclose(fp);
    if (nread == 0) {
        send_status(sfd, -1);
        return;
    }

    root = json_object();
    json_object_set_new(root, "status", json_integer(0));
    json_object_set_new(root, "commandline", json_stringn(cmdline, nread));
    send_json(sfd, root);
    json_decref(root);
}


static void handle_get_modules(int sfd, pid_t pid, json_t *json)
{
    char fname[64] = {0};
    FILE *fp = NULL;
    char line[256] = {0};
    char *start = NULL, *end = NULL, *name = NULL;
    char *last_start = NULL, *last_end = NULL, *last_name = NULL;
    json_t *root = NULL;
    json_t *module_list = NULL;
    json_t *module = NULL;

    UNREFERENCED_PARAMETER(json);

    snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
    fp = fopen(fname, "r");
    if (fp == NULL) {
        perror("fopen");
        send_status(sfd, errno);
        return;
    }

    module_list = json_array();
    while (fgets(line, sizeof(line), fp) != NULL) {
        // parse the module start, end, and pathname fields
        start = strtok(line, "-");
        if (start == NULL) continue;

        end = strtok(NULL, " \n");
        if (end == NULL) continue;

        if (strtok(NULL, " \n") == NULL) continue;  // permissions
        if (strtok(NULL, " \n") == NULL) continue;  // offset
        if (strtok(NULL, " \n") == NULL) continue;  // device
        if (strtok(NULL, " \n") == NULL) continue;  // inode

        name = strtok(NULL, " \n");
        if (name == NULL) continue;

        // if we parsed it correctly, record the start, end, and pathname
        if (last_name == NULL) {
            if (name[0] != '[') {
                // no previous entry and this is a real object - record it.
                last_start = strdup(start);
                last_end = strdup(end);
                last_name = strdup(name);
            }
            else {
                // no previous entry and this is an unnamed mapping
                continue;
            }
        }
        else if (strcmp(last_name, name) == 0) {
            // we're already tracking this object - update the end address
            free(last_end);
            last_end = strdup(end);
        }
        else {
            // we're switching to a new object - create a JSON object for the
            // previous one.
            module = json_object();
            json_object_set_new(module, "start", json_string(last_start));
            json_object_set_new(module, "end", json_string(last_end));
            json_object_set_new(module, "name", json_string(last_name));
            json_array_append_new(module_list, module);

            free(last_start);
            free(last_end);
            free(last_name);

            if (name[0] != '[') {
                last_start = strdup(start);
                last_end = strdup(end);
                last_name = strdup(name);
            }
            else {
                last_start = NULL;
                last_end = NULL;
                last_name = NULL;
            }
        }
    }
    fclose(fp);

    // handle the last line in /proc/self/maps
    if (last_name != NULL) {
        module = json_object();
        json_object_set_new(module, "start", json_string(last_start));
        json_object_set_new(module, "end", json_string(last_end));
        json_object_set_new(module, "name", json_string(last_name));
        json_array_append_new(module_list, module);

        free(last_start);
        free(last_end);
        free(last_name);
    }

    root = json_object();
    json_object_set_new(root, "status", json_integer(0));
    json_object_set_new(root, "modules", module_list);
    send_json(sfd, root);
    json_decref(root);
}


static void handle_get_registers(int sfd, pid_t pid, json_t *json)
{
    struct user_regs_struct regs = {0};
    json_t *root = NULL;
    json_t *registers = NULL;

    UNREFERENCED_PARAMETER(json);

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        perror("ptrace");
        send_status(sfd, errno);
        return;
    }

    registers = json_object();
    json_object_set_new(registers, "rax", json_integer(regs.rax));
    json_object_set_new(registers, "rbx", json_integer(regs.rbx));
    json_object_set_new(registers, "rcx", json_integer(regs.rcx));
    json_object_set_new(registers, "rdx", json_integer(regs.rdx));
    json_object_set_new(registers, "rsi", json_integer(regs.rsi));
    json_object_set_new(registers, "rdi", json_integer(regs.rdi));
    json_object_set_new(registers, "rsp", json_integer(regs.rsp));
    json_object_set_new(registers, "rbp", json_integer(regs.rbp));
    json_object_set_new(registers, "r8", json_integer(regs.r8));
    json_object_set_new(registers, "r9", json_integer(regs.r9));
    json_object_set_new(registers, "r10", json_integer(regs.r10));
    json_object_set_new(registers, "r11", json_integer(regs.r11));
    json_object_set_new(registers, "r12", json_integer(regs.r12));
    json_object_set_new(registers, "r13", json_integer(regs.r13));
    json_object_set_new(registers, "r14", json_integer(regs.r14));
    json_object_set_new(registers, "r15", json_integer(regs.r15));
    json_object_set_new(registers, "rip", json_integer(regs.rip));
    json_object_set_new(registers, "eflags", json_integer(regs.eflags));
    json_object_set_new(registers, "cs", json_integer(regs.cs));
    json_object_set_new(registers, "ds", json_integer(regs.ds));
    json_object_set_new(registers, "es", json_integer(regs.es));
    json_object_set_new(registers, "fs", json_integer(regs.fs));
    json_object_set_new(registers, "gs", json_integer(regs.gs));
    json_object_set_new(registers, "ss", json_integer(regs.ss));
    json_object_set_new(registers, "fsbase", json_integer(regs.fs_base));
    json_object_set_new(registers, "gsbase", json_integer(regs.gs_base));

    root = json_object();
    json_object_set_new(root, "status", json_integer(0));
    json_object_set_new(root, "registers", registers);
    send_json(sfd, root);
    json_decref(root);
}


static void handle_get_bytes(int sfd, pid_t pid, json_t *json)
{
    json_t *address_val = NULL;
    json_t *size_val = NULL;
    unsigned long long address = 0;
    unsigned long long size = 0;
    unsigned long long peek_size = 0;
    char *buffer = NULL;
    unsigned long long i = 0;
    long val = 0;
    char *buffer_b64 = NULL;
    size_t b64_size = 0;
    json_t *root = NULL;

    // get the address and size from the params
    address_val = json_object_get(json, "address");
    size_val = json_object_get(json, "size");
    if (address_val == NULL || size_val == NULL) {
        send_status(sfd, -1);
        return;
    }

    address = json_integer_value(address_val);
    size = json_integer_value(size_val);

    // round up to the nearest multiple of sizeof(long) for ptrace
    peek_size = size + (sizeof(long) - (size % sizeof(long)));
    buffer = calloc(1, peek_size);
    if (buffer == NULL) {
        send_status(sfd, -1);
        return;
    }

    for (i = 0; i < peek_size / sizeof(long); i++) {
        val = ptrace(PTRACE_PEEKDATA, pid, address + (i * sizeof(long)), NULL);
        ((long *)buffer)[i] = val;
    }

    // base64 encode the data
    buffer_b64 = base64_encode(buffer, size, &b64_size);
    if (buffer_b64 == NULL) {
        send_status(sfd, -1);
        free(buffer);
        return;
    }

    root = json_object();
    json_object_set_new(root, "status", json_integer(0));
    json_object_set_new(root, "bytes", json_string(buffer_b64));
    send_json(sfd, root);
    json_decref(root);

    free(buffer_b64);
    free(buffer);
}


static void handle_set_bytes(int sfd, pid_t pid, json_t *json)
{
    json_t *address_val = NULL;
    json_t *data_b64_val = NULL;
    unsigned long long address = 0;
    const char *data_b64 = NULL;
    char *data = NULL;
    size_t data_size = 0;
    unsigned long long poke_size = 0;
    unsigned long long i = 0;
    long val = 0;

    // get the address and base64 encoded data from the params
    address_val = json_object_get(json, "address");
    data_b64_val = json_object_get(json, "data");
    if (address_val == NULL || data_b64_val == NULL) {
        send_status(sfd, -1);
        return;
    }

    address = json_integer_value(address_val);
    data_b64 = json_string_value(data_b64_val);

    // base64 decode the data
    data = base64_decode(data_b64, strlen(data_b64), &data_size);
    if (data == NULL) {
        send_status(sfd, -1);
        return;
    }

    // round up to the nearest multiple of sizeof(long) for ptrace
    poke_size = data_size + (sizeof(long) - (data_size % sizeof(long)));
    for (i = 0; i < poke_size; i += sizeof(long)) {
        val = ptrace(PTRACE_PEEKDATA, pid, address + i, NULL);
        memcpy(&val, data + i, min(data_size - i, sizeof(val)));
        if (ptrace(PTRACE_POKEDATA, pid, address + i, val) != 0) {
            send_status(sfd, -1);
            free(data);
            return;
        }
    }

    send_status(sfd, 0);
    free(data);
}


static void handle_go(int sfd, pid_t pid, json_t *json)
{
    int retval = 0;
    int status = 0;
    json_t *root = NULL;

    UNREFERENCED_PARAMETER(json);

    retval = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if (retval != 0) {
        send_status(sfd, retval);
        return;
    }

    // wait for the child to get a signal
    if (waitpid(pid, &status, 0) == -1) {
        send_status(sfd, errno);
        return;
    }

    root = json_object();
    json_object_set_new(root, "status", json_integer(retval));
    if (WIFEXITED(status)) {
        json_object_set_new(root, "stopval", json_integer(WEXITSTATUS(status)));
        json_object_set_new(root, "exited", json_true());
    }
    else if (WIFSTOPPED(status)) {
        json_object_set_new(root, "stopval", json_integer(WSTOPSIG(status)));
        json_object_set_new(root, "exited", json_false());
    }
    send_json(sfd, root);
    json_decref(root);
}


static void handle_step_instruction(int sfd, pid_t pid, json_t *json)
{
    int retval = 0;
    int status = 0;
    json_t *root = NULL;

    UNREFERENCED_PARAMETER(json);

    retval = ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    if (retval != 0) {
        send_status(sfd, retval);
        return;
    }

    // wait for the child to get a signal
    if (waitpid(pid, &status, 0) == -1) {
        send_status(sfd, errno);
        return;
    }

    root = json_object();
    json_object_set_new(root, "status", json_integer(retval));
    if (WIFEXITED(status)) {
        json_object_set_new(root, "stopval", json_integer(WEXITSTATUS(status)));
        json_object_set_new(root, "exited", json_true());
    }
    else if (WIFSTOPPED(status)) {
        json_object_set_new(root, "stopval", json_integer(WSTOPSIG(status)));
        json_object_set_new(root, "exited", json_false());
    }
    send_json(sfd, root);
    json_decref(root);
}


/**
 * @brief Run a debug session with a connected client and debuggee.
 * @note This function will close sfd and terminate pid before returning.
 * @param sfd Socket fd for a connected client.
 * @param pid PID of the debuggee process.
 * @return 0 on success or -1 on error.
 */
static int run_debug_session(int sfd, pid_t pid)
{
    json_t *json = NULL;
    json_t *cmdval = NULL;
    int cmd = 0;

    while (1) {
        json = recv_json(sfd);
        if (json == NULL) {
            goto recv_error;
        }

        cmdval = json_object_get(json, "command");
        if (cmdval == NULL) {
            fprintf(stderr, "No 'command' field in incoming JSON.\n");
            goto continue_loop;
        }
        cmd = json_integer_value(cmdval);

        switch (cmd) {
        case CMD_GET_COMMANDLINE:
            handle_get_commandline(sfd, pid, json);
            break;
        case CMD_GET_MODULES:
            handle_get_modules(sfd, pid, json);
            break;
        case CMD_GET_REGISTERS:
            handle_get_registers(sfd, pid, json);
            break;
        case CMD_GET_BYTES:
            handle_get_bytes(sfd, pid, json);
            break;
        case CMD_SET_BYTES:
            handle_set_bytes(sfd, pid, json);
            break;
        case CMD_GO:
            handle_go(sfd, pid, json);
            break;
        case CMD_STEP_INSTRUCTION:
            handle_step_instruction(sfd, pid, json);
            break;
        default:
            fprintf(stderr, "Received unknown cmd id: %ul\n", cmd);
        }

continue_loop:
        json_decref(json);
    }

    return 0;

recv_error:
    fprintf(stderr, "[*] Client disconnected. Terminating program.\n");
    kill(pid, SIGTERM);
    close(sfd);
    return 0;
}


/**
 * @brief Start and trace the debuggee process.
 * @param child_argv argv for the debuggee.
 * @return pid of the debuggee or -1 on error.
 */
static int start_debuggee(char **child_argv)
{
    pid_t pid = -1;
    int status = 0;

    pid = fork();
    if (pid == -1) {
        perror("fork");
        return -1;
    }
    else if (pid == 0) {
        // child - request ptrace and exec
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        execv(child_argv[0], child_argv);
        perror("execv");
        _exit(EXIT_FAILURE);
    }

    // parent - wait for the child to get SIGTERM after execv
    if (waitpid(pid, &status, 0) == -1) {
        kill(pid, SIGTERM);
        return -1;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        return pid; // success
    }

    if (!WIFEXITED(status)) {
        kill(pid, SIGTERM);
    }
    return -1;
}


/**
 * @brief Start a debug server and wait for a client to connect.
 * @param ip IP address to bind to.
 * @param port TCP port to bind to.
 * @return socket fd of a connected client or -1 on error.
 */
static int wait_for_connect(char *ip, char *port)
{
    int retval = 0;
    const struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP };
    struct addrinfo *addrinfo = NULL;
    struct addrinfo *addr = NULL;
    int ss = -1;
    int enable = 1;
    int s = -1;

    retval = getaddrinfo(ip, port, &hints, &addrinfo);
    if (retval != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retval));
        return -1;
    }

    for (addr = addrinfo; addr != NULL; addr = addr->ai_next) {
        ss = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (ss == -1) {
            continue;
        }

        if (setsockopt(ss, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
            continue;
        }

        if (bind(ss, addr->ai_addr, addr->ai_addrlen) == 0) {
            break;  // success
        }

        close(ss);
    }
    freeaddrinfo(addrinfo);
    addrinfo = NULL;

    if (addr == NULL) {
        fprintf(stderr, "Invalid ip:port address\n");
        return -1;
    }

    if (listen(ss, SOMAXCONN) != 0) {
        perror("listen");
        close(ss);
        return -1;
    }

    s = accept(ss, NULL, NULL);
    close(ss);

    if (s == -1) {
        perror("accept");
    }
    return s;
}


__attribute__((noreturn)) static void usage_exit(char *program)
{
    fprintf(stderr, "Usage: %s [-i IP] [-p PORT] <cmdline>\n", program);
    exit(EXIT_FAILURE);
}


int main(int argc, char *argv[])
{
    int c = -1;
    int option_index = 0;
    char *arg_ip = DEFAULT_BIND_IP;
    char *arg_port = DEFAULT_BIND_PORT;
    char **arg_child_argv = NULL;
    int sfd = -1;
    pid_t pid = -1;

    while (1) {
        static struct option long_options[] = {
            {"ip",   required_argument, 0, 0},
            {"port", required_argument, 0, 0},
            {"help", no_argument,       0, 0},
        };

        c = getopt_long(argc, argv, "i:p:h", long_options, &option_index);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'i':
            arg_ip = optarg;
            break;
        case 'p':
            arg_port = optarg;
            break;
        case 'h':
            usage_exit(argv[0]);
        default:
            fprintf(stderr, "Unknown option\n");
            usage_exit(argv[0]);
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "No cmdline specified!\n");
        usage_exit(argv[0]);
    }
    arg_child_argv = &argv[optind];

    sfd = wait_for_connect(arg_ip, arg_port);
    if (sfd == -1) {
        exit(EXIT_FAILURE);
    }
    (void)fcntl(sfd, F_SETFD, FD_CLOEXEC);

    fprintf(stderr, "[+] Received client connection\n");
    fprintf(stderr, "[*] Starting program...\n");

    pid = start_debuggee(arg_child_argv);
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    return run_debug_session(sfd, pid);
}
