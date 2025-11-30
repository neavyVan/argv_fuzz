// Tesseract Modified Start
#include <math.h>
#include <string.h>
#include "../include/afl-fuzz.h"

/* 
    我获取了测试用例的文件路径，我现在要打开这个文件，并且读取每一行的程序选项
    把@@替换为AFL的输入目录，并且我要执行每一行程序选项，做一个排名
    然后使用加权，给每行一个概率，以用于后续的随机选择
*/

char **read_argvs_file_1(const char *path, int *argc_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return NULL;
    }

    char **argv = NULL;
    int argc = 0;

    // 读取整个文件到内存
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    u8 *buf = malloc(size);
    fread(buf, 1, size, fp);
    fclose(fp);

    // 遍历 buffer，按 '\0' 分割
    u8 *p = buf;
    u8 *end = buf + size;

    while (p < end) {
        size_t len = strlen((char *)p);

        // 防止文件末尾意外损坏
        if (len == 0) {
            p++;
            continue;
        }

        argv = realloc(argv, sizeof(char *) * (argc + 1));
        argv[argc] = strdup((char *)p);
        argc++;

        // 跳到下一个字符串（跳过 '\0'）
        p += len + 1;
    }

    // 最后加 NULL
    argv = realloc(argv, sizeof(char *) * (argc + 1));
    argv[argc] = NULL;

    if (argc_out)
        *argc_out = argc;

    free(buf);
    return argv;
}

// 这个好像是取代原本的参数文件
void write_argvs_file(afl_state_t *afl)
{
    //删除文件，这个是afl原始的生成文件
    unlink(afl->fsrv.argvs_file);
    s32 fd = open(afl->fsrv.argvs_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", afl->fsrv.argvs_file); }

    u32 i = 0;
    
    // 替代原本的文件
    while(afl->argv[i] != NULL) {

        // replace @@ with /tmp_dir/.cur_input*
        if(strstr(afl->argv[i], "@@")) {
            ck_write(fd, afl->fsrv.out_file, strlen(afl->fsrv.out_file) + 1, afl->fsrv.argvs_file);
        }
        else {
            ck_write(fd, afl->argv[i], strlen(afl->argv[i]) + 1 , afl->fsrv.argvs_file);
        }
        ++i;
    }

    close(fd);
    // char ** hihi=read_argvs_file_1(afl->fsrv.argvs_file, NULL);
    return;
}

double get_random(double max_random){
    double random = (double)rand() / (double)RAND_MAX;
    return random * max_random;
}

int binary_search(CmdNode *data,int len, double random_weight){
    int left = 0, right = len - 1;
    while (left < right) {
        int mid = (left + right) / 2;
        if (random_weight <= data[mid].prefix_weight){
            right = mid;
        }else{
            left = mid + 1;
        }
    }
    return left;
}

CmdNode parse_line(const char *line){
    double ALPHA = 1.5;
    CmdNode node;
    node.argv = NULL;
    node.argc = 0;
    node.score = 0;
    node.weight = 0;
    node.prefix_weight = 0;
    node.has_fuzzed = 0;
    char *copy = strdup(line);
    if (!copy) {
        perror("strdup failed");
        exit(1);
    }

    // 解析分数
    char *colon = strchr(copy, ':');
    if (!colon) {
        fprintf(stderr, "Invalid line format: %s\n", line);
        free(copy);
        exit(1);
    }
    *colon = '\0';
    node.score = atof(copy);

    // 解析命令行参数
    char *cmd = colon + 1;
    int capacity = 4;
    node.argv = malloc(capacity * sizeof(char *));
    if (!node.argv) {
        perror("malloc failed");
        exit(1);
    }

    char *token = strtok(cmd, " \t\n");
    while (token) {
        if (node.argc >= capacity) {
            capacity *= 2;
            node.argv = realloc(node.argv, (capacity+1) * sizeof(char *));
            if (!node.argv) {
                perror("realloc failed");
                exit(1);
            }
        }
        node.argv[node.argc++] = strdup(token);
        token = strtok(NULL, " \t\n");
    }
    node.argv[node.argc] = NULL;  // 添加空指针作为结束标志
    node.weight = pow(node.score, ALPHA);
    free(copy);
    return node;
}

u8 __attribute__((hot)) tesseract_common_fuzz_stuff(afl_state_t *afl, u8 *out_buf,
                                          u32 len) {

    u8 fault;

  if (unlikely(len = write_to_testcase(afl, (void **)&out_buf, len, 0)) == 0) {

    return 0;

  }
//   printf("skip_deterministic: %d\n", afl->skip_deterministic);
    // printf("doing_det: %d\n", afl->doing_det);
    // printf("queue_cur: %p\n", afl->queue_cur);

  fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  return 0;
}

// 释放 CmdNode 的内存
void free_cmdnode(CmdNode *node) {
    for (int i = 0; i < node->argc; i++) {
        free(node->argv[i]);
    }
    free(node->argv);
}

void argvs_fuzz_init(afl_state_t *afl){
    srand((unsigned)time(NULL));
    printf("argvs_fuzz_init\n");
    char file_path[1024];
    snprintf(file_path, sizeof(file_path), "%s", afl->argvs_path);
    FILE *file = fopen(file_path, "r");  // 打开文件
    if (!file) {
        FATAL("open file error, path: %s\n", afl->argvs_path);
        return;
    }

    // 初始分配内存，假设文件有100行
    int capacity = 5;
    afl->argvs_cmdNodes = (CmdNode *)malloc(capacity * sizeof(CmdNode));
    if (!afl->argvs_cmdNodes) {
        fclose(file);
        FATAL("malloc error when afl_fuzz_argv_init");
        return;
    }

    int count = 0;
    char line[1024];  // 用于存储每一行数据
    // 读取每一行
    while (fgets(line, sizeof(line), file)) {
        // 解析每一行数据
        // if (sscanf(line, "%lf:%[^\n]", &afl->argvs_cmdNodes[i].score, line) == 2) {
        //     // // 动态分配内存给 cmdline
        //     // char *token = strtok(line, " ");
        //     // afl->argvs_cmdNodes[i].argv = (char **)malloc(strlen(token)*sizeof(char));
        //     // if (afl->argvs_cmdNodes[i].argv == NULL) {
        //     //     fclose(file);
        //     //     FATAL("malloc error when afl_fuzz_argv_init");
        //     //     return ;
        //     // }
        //     // strcpy(afl->argvs_cmdNodes[i].argv, line); // 存储命令行
        //     // afl->argvs_cmdNodes[i].weight = pow(afl->argvs_cmdNodes[i].score, ALPHA);
        //     // if (i==0) {
        //     //     afl->argvs_cmdNodes[i].prefix_weight = 0;
        //     // }else{
        //     //     afl->argvs_cmdNodes[i].prefix_weight = afl->argvs_cmdNodes[i-1].prefix_weight + afl->argvs_cmdNodes[i-1].weight;
        //     // }
        // }
        // 如果数据量超过当前容量，增加内存
        if (count >= capacity) {
            capacity *= 1.5;  // 扩展容量为原来的1.5倍
            afl->argvs_cmdNodes = (CmdNode *)realloc(afl->argvs_cmdNodes, capacity * sizeof(CmdNode));
            if (!afl->argvs_cmdNodes) {
                fclose(file);
                FATAL("malloc error when afl_fuzz_argv_init");
                return ;
            }
        }
        afl->argvs_cmdNodes[count] = parse_line(line);

        

        if(count==0){
            afl->argvs_cmdNodes[count].prefix_weight = 0;
        }else{
            afl->argvs_cmdNodes[count].prefix_weight = afl->argvs_cmdNodes[count-1].prefix_weight + afl->argvs_cmdNodes[count-1].weight;
        }
        count++;
    }
    fclose(file);
    afl->argvs_total_weight = afl->argvs_cmdNodes[count-1].prefix_weight+afl->argvs_cmdNodes[count-1].weight;
    afl->argvs_cmdNum = count;
    afl->current_cmdNum = 0;


    // get_random_argvs(afl);
    tesseract_save_cmdline(afl);//把cmd写到了afl->current_argv里
    afl->current_argv_timeout = get_cur_time() + 10 * 60 * 1000;
    afl->current_argv_start_fuzztime = get_cur_time();
    afl->init_seed_count = afl->queued_items;
    
    printf("argvs_fuzz_init end\n");
    return;
}
//测试当前选择的argv面对初始种子，是否有影响覆盖率的能力，是否有真是增加覆盖率，如果有增加，则采用，没有增加，就不采用（因为我们这里是宏观的路径）
u8 run_argvs(afl_state_t *afl){
    u32 len, temp_len;
    u32 idx1;
    u8 *orig_in, *out_buf;
    struct queue_entry *cur_tc;
    u8 ret=0;
    u32 origin_count = afl->queued_items+afl->saved_crashes;
    for (idx1 = 0; idx1 < afl->init_seed_count; ++idx1) {

        cur_tc = afl->queue_buf[idx1];
        // afl->cur_depth = afl->queue_cur->depth;

        len = (u32) cur_tc->len;
        orig_in = queue_testcase_get(afl, cur_tc);

        out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
        if (unlikely(!out_buf)) { PFATAL("alloc"); }
        memcpy(out_buf, orig_in, len);
        temp_len = len;


        common_fuzz_stuff(afl, out_buf, temp_len);

        if(afl->queued_items+afl->saved_crashes>origin_count){
            ret = 2;
        }

        
    }
    show_stats(afl);
    
    return ret;
}

void get_random_argvs(afl_state_t *afl){
    u8 ret=0;
    u8 count=0;
    do{
        
        // 取一个随机数，范围是0-total_weight，用这个概率选择一个命令行
        if(afl->argvs_cmdNum==0){
            FATAL("no argvs file");
            return;
        }
        int index = 0;
        if(afl->current_cmdNum==afl->argvs_cmdNum){
            afl->current_cmdNum = 0;
            for(int i=0;i<afl->argvs_cmdNum;i++){
                afl->argvs_cmdNodes[i].has_fuzzed = 0;
            }
        }
        do{
            double random_weight = get_random(afl->argvs_total_weight);
            index = binary_search(afl->argvs_cmdNodes, afl->argvs_cmdNum, random_weight);
            afl->argv = afl->argvs_cmdNodes[index].argv;
            // afl->fsrv.argv = afl->argvs_cmdNodes[index].argv;
            write_argvs_file(afl);
            if(afl->argvs_cmdNodes[index].has_fuzzed == 0){
                afl->argvs_cmdNodes[index].has_fuzzed = 1;
                afl->current_cmdNum++;
                break;
            }
            afl->argvs_cmdNodes[index].has_fuzzed = 1;
            afl->current_cmdNum++;
        }while(afl->argvs_cmdNodes[index].has_fuzzed==1&&afl->current_cmdNum<afl->argvs_cmdNum);

        
        show_stats(afl);
        for(int i=0;i<afl->argvs_cmdNodes[index].argc;i++){
            u8 *aa_loc = strstr(afl->argvs_cmdNodes[index].argv[i], "@@");
            if(aa_loc!=NULL){
                detect_file_args(afl->argvs_cmdNodes[index].argv, afl->fsrv.out_file, &afl->fsrv.use_stdin);
                break;
            }
        }

        //重启fsrv
        // u32 map_size=afl->fsrv.map_size;
        // if(!afl->fsrv.trace_bits){
        //     afl->fsrv.trace_bits =
        //     afl_shm_init(&afl->shm, afl->fsrv.map_size, afl->non_instrumented_mode,
        //                 afl->perm, afl->chown_needed ? afl->fsrv.gid : -1);

        //     if (!afl->non_instrumented_mode && !afl->unicorn_mode &&
        //         !afl->fsrv.frida_mode && !afl->fsrv.cs_mode &&
        //         !afl->afl_env.afl_skip_bin_check) {

        //         if (map_size <= DEFAULT_SHMEM_SIZE) {

        //         afl->fsrv.map_size = DEFAULT_SHMEM_SIZE;  // dummy temporary value
        //         char vbuf[16];
        //         snprintf(vbuf, sizeof(vbuf), "%u", DEFAULT_SHMEM_SIZE);
        //         setenv("AFL_MAP_SIZE", vbuf, 1);

        //         }
        //     }
        // }
        // u32 old_size = afl->fsrv.map_size;
        afl_fsrv_kill(&afl->fsrv);
        // u32 new_size =
        //     afl_fsrv_get_mapsize(&afl->fsrv, afl->argv, &afl->stop_soon,
        //                     afl->afl_env.afl_debug_child);
        // resize all buffers (virgin_bits, var_bytes, etc)
        // afl_resize_map_buffers(afl, old_size, new_size);
        // afl_shm_deinit(&afl->shm);
        // afl->fsrv.trace_bits = afl_shm_init(&afl->shm, new_size, afl->non_instrumented_mode,
        //                 afl->perm, afl->chown_needed ? afl->fsrv.gid : -1);
        afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                        afl->afl_env.afl_debug_child);
        // clear trace map
        memset(afl->fsrv.trace_bits, 0, afl->fsrv.map_size);

        tesseract_save_cmdline(afl);//把cmd写到了afl->current_argv里
        write_argvs_file(afl);
        ret = run_argvs(afl);
        count++;

    }while( ret!=2 && (afl->current_cmdNum<afl->argvs_cmdNum) );
    return;
}

void tesseract_save_cmdline(afl_state_t *afl) {

  u32 len = 1, i=0;
  u8 *buf;
  char **temp_argv=afl->argv;
  while (temp_argv!=NULL&&*temp_argv!=NULL) {

    len += strlen(afl->argv[i++]) + 1;
    temp_argv++;

  }
  u32 argc = i;
  ck_free(afl->current_argv);
  buf  = afl->current_argv = ck_alloc(len);

  for (i = 0; i < argc; ++i) {

    u32 l = strlen(afl->argv[i]);

    if (!afl->argv[i] || !buf) { FATAL("null deref detected"); }

    memcpy(buf, afl->argv[i], l);
    buf += l;

    if (i != argc - 1) { *(buf++) = ' '; }

  }
  *buf=0;
  return;

}


// Tesseract Modified End