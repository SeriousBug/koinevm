// C++ through the rootfs's own libstdc++: allocation, the containers, and the exception machinery,
// which reaches the unwinder in libgcc and the personality routine in libstdc++.
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <bits/hashtable_policy.h>
#include <stdexcept>
#include <string>
#include <vector>

static void containers() {
    std::vector<int> v;
    for (int i = 0; i < 1000; i++) v.push_back((i * 37) % 101);
    std::sort(v.begin(), v.end());
    std::map<std::string, int> counts;
    for (int x : v) counts[std::to_string(x)]++;
    std::cout << "sorted " << v.front() << " " << v.back() << " distinct " << counts.size() << "\n";
    auto *heap = new std::string(200, 'x');
    std::cout << "heap " << heap->size() << " " << heap->substr(0, 3) << "\n";
    delete heap;
    std::unique_ptr<std::vector<int>> owned(new std::vector<int>{1, 2, 3});
    std::cout << "owned " << owned->size() << "\n";
}

static int depth(int n) {
    if (n == 0) throw std::runtime_error("deep");
    return depth(n - 1) + 1;
}

static void exceptions() {
    try {
        depth(8);
    } catch (const std::runtime_error &e) {
        std::cout << "caught " << e.what() << "\n";
    }
    try {
        throw std::out_of_range("range");
    } catch (const std::exception &e) {
        std::cout << "caught base " << e.what() << "\n";
    }
    try {
        std::string().at(3);
    } catch (const std::out_of_range &e) {
        std::cout << "at " << std::string(e.what()).size() << "\n";
    }
}

// The variable substitution the architecture tables need: find a marker, replace it, and carry on
// from after the replacement. A guard makes a loop that would never end finite, so the count shows
// up in the oracle rather than hanging the run.
static void substitute() {
    std::string arch = "base-uclibc-linux-<cpu>";
    std::string cpu = "arm64";
    unsigned steps = 0;
    size_t pos = 0;
    while ((pos = arch.find("<cpu>", pos)) != std::string::npos) {
        if (++steps > 50) break;
        arch.replace(pos, 5, cpu);
        pos += cpu.size();
    }
    std::cout << "subst " << arch << " " << steps << "\n";
    std::string many = "a<cpu>b<cpu>c<cpu>";
    steps = 0;
    while (steps < 50) {
        size_t at = many.find("<cpu>");
        if (at == std::string::npos) break;
        steps++;
        many.replace(at, 5, "ZZ");
    }
    std::cout << "subst2 " << many << " " << steps << "\n";
    std::string edge = "<cpu><cpu><cpu>";
    steps = 0;
    while ((pos = edge.find("<cpu>", pos)) != std::string::npos) {
        if (++steps > 50) break;
        edge.replace(pos, 5, "");
    }
    std::cout << "subst3 " << edge.size() << " " << steps << "\n";
}

// apt's architecture tables, line for line: the same split, the same getline loop, the same
// substitution. A cap on the number of lines turns a loop that would never end into a number the
// oracle can compare.
static std::vector<std::string> split(const std::string &s) {
    std::vector<std::string> vec;
    std::istringstream iss(s);
    iss.imbue(std::locale::classic());
    for (std::string current_s; iss >> current_s;) vec.push_back(current_s);
    return vec;
}

static std::string subst(const std::string &str, const std::string &subst, const std::string &with) {
    std::string result = str;
    std::string::size_type pos = 0;
    unsigned steps = 0;
    while (true) {
        pos = result.find(subst, pos);
        if (pos == std::string::npos) break;
        if (++steps > 100) break;
        result.replace(pos, subst.length(), with);
        pos += with.length();
    }
    return result;
}

static void tables() {
    std::vector<std::string> cpus;
    std::ifstream cputable("/usr/share/dpkg/cputable");
    unsigned lines = 0;
    for (std::string cpuline; std::getline(cputable, cpuline);) {
        if (++lines > 400) break;
        if (cpuline[0] == '#' || cpuline[0] == '\0') continue;
        auto row = split(cpuline);
        cpus.push_back(row.at(0));
    }
    std::cout << "cpus " << cpus.size() << " lines " << lines << " eof " << cputable.eof() << "\n";

    std::ifstream tupletable("/usr/share/dpkg/tupletable");
    unsigned tuples = 0, subbed = 0;
    for (std::string tupleline; std::getline(tupletable, tupleline);) {
        if (++tuples > 400) break;
        if (tupleline[0] == '#' || tupleline[0] == '\0') continue;
        auto row = split(tupleline);
        auto tuple = row.at(0);
        auto arch = row.at(1);
        if (tuple.find("<cpu>") == std::string::npos && arch.find("<cpu>") == std::string::npos) {
            if (tuples < 3) std::cout << "tuple " << arch << "\n";
        } else {
            subbed++;
            for (auto &&cpu : cpus) {
                auto mytuple = subst(tuple, "<cpu>", cpu);
                auto myarch = subst(arch, "<cpu>", cpu);
                if (subbed == 1 && myarch == "uclibc-linux-arm")
                    std::cout << "first " << mytuple << " " << myarch << "\n";
            }
        }
    }
    std::cout << "tuples " << tuples << " subbed " << subbed << " eof " << tupletable.eof() << "\n";
}

// A float member widened to double, floored and converted to a size: the rehash policy's next
// resize, which decides whether the next insert rehashes.
static void loadfactor() {
    struct Policy {
        float factor;
        std::size_t next;
    } p;
    p.factor = 1.0f;
    p.next = 0;
    for (unsigned i = 1; i < 6; i++) {
        double wide = p.factor;
        double product = i * wide;
        p.next = (std::size_t)__builtin_floor(product);
        std::cout << "lf " << i << " " << wide << " " << product << " " << p.next << std::endl;
    }
    Policy copy = p;
    std::cout << "lf copy " << copy.factor << " " << copy.next << std::endl;
}

// The rehash policy on its own: the bucket count it picks for a small number of elements is what
// decides how large an unordered_map grows.
static void policy() {
    std::__detail::_Prime_rehash_policy p(1.0f);
    for (std::size_t n = 0; n < 16; n++) {
        auto const buckets = p._M_next_bkt(n);
        std::cout << "bkt " << n << " " << buckets << " next " << p._M_next_resize << std::endl;
    }
    std::size_t next = 0;
    for (std::size_t elts = 0; elts < 16; elts++) {
        auto const need = p._M_need_rehash(next, elts, 1);
        std::cout << "need " << elts << " " << need.first << " " << need.second << std::endl;
        if (need.first) next = need.second;
    }
}

// The hashtable apt's architecture map uses, filled the same way: an unordered_map of string to
// vector<string>, with enough entries to rehash several times.
static void hashtable() {
    std::unordered_map<std::string, std::vector<std::string>> map;
    for (int i = 0; i < 20000; i++) {
        if (i % 1024 == 0) std::cout << "at " << i << " buckets " << map.bucket_count() << std::endl;
        std::vector<std::string> value;
        value.push_back("cpu");
        value.push_back(std::to_string(i % 97));
        map.insert({std::string("arch-") + std::to_string(i), value});
    }
    unsigned long total = 0;
    for (const auto &kv : map) total += kv.first.size() + kv.second.size();
    std::cout << "map " << map.size() << " " << total << " " << map.count("arch-19999") << "\n";
    std::cout << "hash " << std::hash<std::string>{}("base-uclibc-linux-arm64") << "\n";
    std::cout << "bucket " << map.bucket("arch-5") << " " << map.bucket_count() << "\n";
}

int main() {
    std::cout << "hello from c++" << std::endl;
    containers();
    substitute();
    tables();
    loadfactor();
    policy();
    hashtable();
    exceptions();
    std::cout << "cxx: done" << std::endl;
    return 0;
}
