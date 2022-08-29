/* Copyright 2021 Aristocratos (jakob@qvantnet.com)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

indent = tab
tab-size = 4
*/
#pragma warning (disable : 4455 4244 6305 26819)
#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <atomic>
#include <deque>
#include <robin_hood.h>
#include <array>
#include <tuple>

using std::string, std::vector, std::deque, robin_hood::unordered_flat_map, std::atomic, std::array, std::tuple;

void term_resize(bool force=false);

extern void clean_quit(int sig);

namespace Global {
	extern const vector<array<string, 2>> Banner_src;
	extern const string Version;
	extern atomic<bool> quitting;
	extern string exit_error_msg;
	extern atomic<bool> thread_exception;
	extern string banner;
	extern atomic<bool> resized;
	extern string overlay;
	extern string clock;
	const string bg_black = "\033[0;40m";
	const string fg_white = "\033[1;97m";
	const string fg_green = "\033[1;92m";
	const string fg_red = "\033[0;91m";
}

namespace Runner {

	extern atomic<bool> active;
	extern atomic<bool> reading;
	extern atomic<bool> stopping;
	extern atomic<bool> redraw;
	extern bool pause_output;
	extern string debug_bg;

	void run(const string& box="", const bool no_update=false, const bool force_redraw=false);
	void stop();

}

namespace Tools {
	//* Platform specific function for system_uptime (seconds since last restart)
	double system_uptime();
}

namespace Shared {
	//* Initialize platform specific needed variables and check for errors
	void init();

	extern long coreCount, page_size, clk_tck;
}


namespace Cpu {
	extern string box;
	extern int x, y, width, height, min_width, min_height;
	extern bool shown, redraw, got_sensors, cpu_temp_only, has_battery;
	extern string cpuName, cpuHz;
	extern vector<string> available_fields;
	extern vector<string> available_sensors;
	extern tuple<int, long, string> current_bat;
	extern string gpu_name;
	extern string gpu_clock;
	extern bool has_gpu;
	extern atomic<uint64_t> smiTimer;
	extern atomic<uint64_t> OHMRTimer;

	struct GpuRaw {
		uint64_t usage = 0;
		uint64_t mem_total = 0;
		uint64_t mem_used = 0;
		uint64_t temp = 0;
		bool cpu_gpu = false;
		string clock_mhz;
	};

	struct OHMRraw {
		unordered_flat_map<string, GpuRaw> GPUS;
		vector<int> CPU;
		int CpuClock = 0;
	};

	struct cpu_info {
		unordered_flat_map<string, deque<long long>> cpu_percent = {
			{"total", {}},
			{"kernel", {}},
			{"user", {}},
			{"dpc", {}},
			{"interrupt", {}},
			{"idle", {}},
			{"gpu", {}}
		};
		vector<deque<long long>> core_percent;
		vector<deque<long long>> temp;
		deque<long long> gpu_temp;
		long long temp_max = 100;
		array<float, 3> load_avg;
	};

	//* Collect cpu stats and temperatures
	auto collect(const bool no_update=false) -> cpu_info&;

	//* Draw contents of cpu box using <cpu> as source
	string draw(const cpu_info& cpu, const bool force_redraw=false, const bool data_same=false);

	extern unordered_flat_map<int, int> core_mapping;
}

namespace Mem {
	extern string box;
	extern int x, y, width, height, min_width, min_height;
	extern bool has_swap, shown, redraw;
	extern int disk_ios;
	extern int64_t totalMem;
	extern bool cpu_gpu;

	struct disk_info {
		string name;
		int64_t total = 0, used = 0, free = 0;
		int used_percent = 0, free_percent = 0;
		array<int64_t, 3> old_io = {0, 0, 0};
		deque<long long> io_read = {};
		deque<long long> io_write = {};
		deque<long long> io_activity = {};
	};

	struct mem_info {
		unordered_flat_map<string, uint64_t> stats =
		{ {"total", 0}, {"used", 0}, {"available", 0}, {"commit", 0}, {"commit_total", 0}, {"cached", 0},
			{"page_total", 0}, {"page_used", 0}, {"page_free", 0}, {"gpu_total", 0}, {"gpu_used", 0}, {"gpu_free", 0} };
		unordered_flat_map<string, deque<long long>> percent =
		{ {"used", {}}, {"available", {}}, {"commit", {}}, {"cached", {}},
			{"page_used", {}}, {"page_free", {}}, {"gpu_used", {}}, {"gpu_free", {}} };
		unordered_flat_map<string, disk_info> disks;
		vector<string> disks_order;
		bool pagevirt = false;
	};

	//* Collect mem & disks stats
	auto collect(const bool no_update=false) -> mem_info&;

	//* Draw contents of mem box using <mem> as source
	string draw(const mem_info& mem, const bool force_redraw=false, const bool data_same=false);
}

namespace Net {
	extern string box;
	extern int x, y, width, height, min_width, min_height;
	extern bool shown, redraw;
	extern string selected_iface;
	extern vector<string> interfaces;
	extern bool rescale;
	extern unordered_flat_map<string, uint64_t> graph_max;

	struct net_stat {
		uint64_t speed = 0, top = 0, total = 0, last = 0, offset = 0, rollover = 0;
	};

	struct net_info {
		unordered_flat_map<string, deque<long long>> bandwidth = { {"download", {}}, {"upload", {}} };
		unordered_flat_map<string, net_stat> stat = { {"download", {}}, {"upload", {}} };
		string ipv4 = "", ipv6 = "";
		bool connected = false;
	};

	extern unordered_flat_map<string, net_info> current_net;

	//* Collect net upload/download stats
	auto collect(const bool no_update=false) -> net_info&;

	//* Draw contents of net box using <net> as source
	string draw(const net_info& net, const bool force_redraw=false, const bool data_same=false);
}

namespace Proc {
	extern atomic<int> numpids;

	extern string box;
	extern int x, y, width, height, min_width, min_height;
	extern bool shown, redraw;
	extern int select_max;
	extern atomic<int> detailed_pid;
	extern int selected_pid, start, selected, collapse, expand, selected_depth;
	extern string selected_name;
	extern string selected_status;
	extern atomic<uint64_t> WMItimer;
	extern bool services_swap;

	//? Contains the valid sorting options for processes
	const vector<string> sort_vector = {
		"pid",
		"name",
		"command",
		"threads",
		"user",
		"memory",
		"cpu direct",
		"cpu lazy",
	};

	//? Contains the valid sorting options for services
	const vector<string> sort_vector_service = {
		"service",
		"caption",
		"status",
		"memory",
		"cpu direct",
		"cpu lazy",
	};

	//? Translation from process state char to explanative string
	const unordered_flat_map<char, string> proc_states = {
		{'R', "Running"},
		{'S', "Sleeping"},
		{'D', "Waiting"},
		{'Z', "Zombie"},
		{'T', "Stopped"},
		{'t', "Tracing"},
		{'X', "Dead"},
		{'x', "Dead"},
		{'K', "Wakekill"},
		{'W', "Unknown"},
		{'P', "Parked"}
	};

	//* Container for process information
	struct proc_info {
		size_t pid = 0;
		string name = "", cmd = "";
		string short_cmd = "";
		size_t threads = 0;
		string user = "";
		uint64_t mem = 0;
		double cpu_p = 0.0, cpu_c = 0.0;
		char state = '0';
		uint64_t ppid = 0, cpu_s = 0, cpu_t = 0, p_nice = 0;
		string prefix = "";
		size_t depth = 0, tree_index = 0;
		bool collapsed = false, filtered = false, WMI = false;
	};

	//* Container for process info box
	struct detail_container {
		size_t last_pid = 0;
		proc_info entry;
		string elapsed, parent, status, io_read, io_write, memory, owner, start, description, last_name, service_type;
		long long first_mem = -1;
		deque<long long> cpu_percent;
		deque<long long> mem_bytes;
		double mem_percent = 0.0;
		bool can_pause = false;
		bool can_stop = false;
	};

	//? Contains all info for proc detailed box
	extern detail_container detailed;

	//* Collect and sort process information from /proc
	auto collect(const bool no_update=false) -> vector<proc_info>&;

	//* Update current selection and view, returns -1 if no change otherwise the current selection
	int selection(const string& cmd_key);

	//* Draw contents of proc box using <plist> as data source
	string draw(const vector<proc_info>& plist, const bool force_redraw=false, const bool data_same=false);
}
