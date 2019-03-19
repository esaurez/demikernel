#include <arpa/inet.h>
#include <boost/optional.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cassert>
#include <cstring>
#include <dmtr/annot.h>
#include <dmtr/libos.h>
#include <dmtr/wait.h>
#include <iostream>
#include <libos/common/mem.h>
#include <netinet/in.h>
#include <yaml-cpp/yaml.h>

#define ITERATION_COUNT 10000

namespace po = boost::program_options;

int main(int argc, char *argv[])
{
    std::string config_path;
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help", "display usage information")
        ("config-path,c", po::value<std::string>(&config_path)->default_value("./config.yaml"), "specify configuration file");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (access(config_path.c_str(), R_OK) == -1) {
        std::cerr << "Unable to find config file at `" << config_path << "`." << std::endl;
        return -1;
    }

    YAML::Node config = YAML::LoadFile(config_path);
    boost::optional<std::string> server_ip_addr;
    uint16_t port = 12345;
    YAML::Node node = config["server"]["bind"]["host"];
    if (YAML::NodeType::Scalar == node.Type()) {
        server_ip_addr = node.as<std::string>();
    }
    node = config["server"]["bind"]["port"];
    if (YAML::NodeType::Scalar == node.Type()) {
        port = node.as<uint16_t>();
    }

    struct sockaddr_in saddr = {};
    saddr.sin_family = AF_INET;
    if (boost::none == server_ip_addr) {
        std::cerr << "Listening on `*:" << port << "`..." << std::endl;
        saddr.sin_addr.s_addr = INADDR_ANY;
    } else {
        const char *s = boost::get(server_ip_addr).c_str();
        std::cerr << "Listening on `" << s << ":" << port << "`..." << std::endl;
        if (inet_pton(AF_INET, s, &saddr.sin_addr) != 1) {
            std::cerr << "Unable to parse IP address." << std::endl;
            return -1;
        }
    }
    saddr.sin_port = htons(port);

    DMTR_OK(dmtr_init(argc, argv));

    dmtr_timer_t *pop_timer = NULL;
    DMTR_OK(dmtr_newtimer(&pop_timer, "pop"));
    dmtr_timer_t *push_timer = NULL;
    DMTR_OK(dmtr_newtimer(&push_timer, "push"));

    int qd = 0;
    DMTR_OK(dmtr_socket(&qd, AF_INET, SOCK_DGRAM, 0));
    printf("server qd:\t%d\n", qd);

    DMTR_OK(dmtr_bind(qd, reinterpret_cast<struct sockaddr *>(&saddr), sizeof(saddr)));

    for (size_t i = 0; i < ITERATION_COUNT; i++) {
        dmtr_qresult_t qr = {};
        dmtr_qtoken_t qt = 0;
        DMTR_OK(dmtr_starttimer(pop_timer));
        DMTR_OK(dmtr_pop(&qt, qd));
        DMTR_OK(dmtr_wait(&qr, qt));
        DMTR_OK(dmtr_stoptimer(pop_timer));
        assert(DMTR_OPC_POP == qr.qr_opcode);
        assert(qr.qr_value.sga.sga_numsegs == 1);

        //fprintf(stderr, "[%lu] server: rcvd\t%s\tbuf size:\t%d\n", i, reinterpret_cast<char *>(qr.qr_value.sga.sga_segs[0].sgaseg_buf), qr.qr_value.sga.sga_segs[0].sgaseg_len);
        DMTR_OK(dmtr_starttimer(push_timer));
        DMTR_OK(dmtr_push(&qt, qd, &qr.qr_value.sga));
        DMTR_OK(dmtr_wait(NULL, qt));
        DMTR_OK(dmtr_stoptimer(push_timer));

        //fprintf(stderr, "send complete.\n");
        free(qr.qr_value.sga.sga_buf);
    }

    DMTR_OK(dmtr_dumptimer(stderr, pop_timer));
    DMTR_OK(dmtr_dumptimer(stderr, push_timer));
    DMTR_OK(dmtr_close(qd));
    return 0;
}