#include <err.h>
#include <iostream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <chrono>
#include <stack>
#include <sys/time.h>
#include <sys/resource.h>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <gtest/gtest.h>
#include "pfs_spdk.h"
#include "pfs_api.h"
#include "pfs_option.h"

using namespace std;

DEFINE_string(cluster, "", "cluster name");
DEFINE_int32(host_id, 1, "hosit id");
DEFINE_string(pbd_name, "", "pbdname name");                       
DEFINE_string(spdk_nvme_controller, "", "nvme controller");                       

extern int                                                                             
pfs_spdk_dev_io_get_cpu_stats(const char *devname,                              
        uint64_t * busy_tsc, uint64_t *idle_tsc);

int main(int argc, char **argv)
{
	gflags::ParseCommandLineFlags(&argc, &argv, true);

	int hostid = FLAGS_host_id;
	string cluster = FLAGS_cluster;
	string pbdname = FLAGS_pbd_name;

	pfs_option_set("spdk_nvme_controller", FLAGS_spdk_nvme_controller.c_str());

	if (cluster.empty()) {
		std::cout << "cluster is empty";
		return 1;
	}
	if (pbdname.empty()) {
		std::cout << "pbd_name is empty";
		return 1;
	}

        if (pfs_spdk_setup()) {
		std::cerr << "can not init spdk";
                return 1;
        }
	                                                                               
	int flags = MNTFLG_RDWR | MNTFLG_LOG;
	int rc = pfs_mount(cluster.c_str(), pbdname.c_str(), hostid, flags);
	if (rc < 0) {                                                              
        	cout << "pfs_mount failed." << endl;                                    
		return 1;
    	} 
	cout << "Setup successful" << endl;       	

	string root="/" + pbdname;
	std::map<ino_t, string> ino_map;
	std::stack<std::string> stk;
	stk.push(root);
#if 0
	pfs_mkdir((root + "/1").c_str(), 0);
	pfs_mkdir((root + "/1" + "/1_1").c_str(), 0);
	pfs_mkdir((root + "/2").c_str(), 0);
#endif
	while (!stk.empty()) {
		string dir_path = stk.top();
		printf("pop %s\n", dir_path.c_str());
		stk.pop();
		DIR *d = pfs_opendir(dir_path.c_str());
		if (d == NULL) {
			err(1, "can not open dir: %s", dir_path.c_str());
		}
		struct dirent *dent;
		while ((dent = pfs_readdir(d))) {
			std::string my_path=dir_path + "/" + dent->d_name;
			if (dent->d_type == DT_DIR) {
				printf("push %s\n", my_path.c_str());
				stk.push(my_path);
				continue;
			}
			if (dent->d_type == DT_UNKNOWN) {
				printf("unknown inode type: %ld %s\n", dent->d_ino, my_path.c_str());
			}
			auto it = ino_map.find(dent->d_ino);
			if (it != ino_map.end()) {
				errx(1, "repeated ino %ld, path1: %s, path2: %s",
					dent->d_ino,
					it->second.c_str(), my_path.c_str());
			} else {
				ino_map[dent->d_ino] = my_path;
				printf("add %ld %s\n", dent->d_ino, my_path.c_str());
			}
		}
	}
	pfs_umount(pbdname.c_str());
	pfs_spdk_cleanup();
	return 0;
}
