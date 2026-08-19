#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include <cstring>
#include <memory>
#include "heversa_api.h"

namespace py = pybind11;

node_local_update_t py_client_mask_update(node_t& node, py::array_t<uint32_t> weights) {
    py::buffer_info buf = weights.request();
    
    if (buf.size != UPDATE_LEN) {
        throw std::runtime_error("Weights array must match compiled UPDATE_LEN.");
    }
    
    uint32_t* ptr = static_cast<uint32_t*>(buf.ptr);
    
    auto out_msg = std::make_unique<node_local_update_t>();
    
    client_mask_update(&node, ptr, out_msg.get());
    return *out_msg;
}

py::array_t<uint32_t> py_server_aggregate_updates(server_t& srv) {
    auto result = py::array_t<uint32_t>(UPDATE_LEN);
    py::buffer_info buf = result.request();
    
    uint32_t* ptr = static_cast<uint32_t*>(buf.ptr);
    
    server_aggregate_updates(&srv, ptr);
    return result;
}

void py_configure_recovery_topology(int num_clients, const std::vector<std::vector<int>>& helper_targets) {
    if (num_clients < 1 || num_clients > MAX_NUM_CLIENTS) {
        throw std::runtime_error("num_clients is outside compiled capacity.");
    }
    if (static_cast<int>(helper_targets.size()) != num_clients) {
        throw std::runtime_error("helper_targets must contain one target list per client.");
    }

    node_set_t topology[MAX_NUM_CLIENTS];
    memset(topology, 0, sizeof(topology));

    for (int helper = 0; helper < num_clients; helper++) {
        for (int target : helper_targets[helper]) {
            if (target < 0 || target >= num_clients) {
                throw std::runtime_error("topology target id is outside the round client range.");
            }
            if (target == helper) {
                throw std::runtime_error("a client cannot be configured as its own recovery helper.");
            }
            node_set_add(&topology[helper], static_cast<node_id_t>(target));
        }
    }

    configure_recovery_topology(num_clients, topology);
}

PYBIND11_MODULE(heversa, m) {
    m.doc() = "Python bindings for the HeVerSa secure aggregation protocol";
    m.attr("UPDATE_LEN") = UPDATE_LEN;
    m.attr("MAX_NUM_CLIENTS") = MAX_NUM_CLIENTS;

    py::class_<server_t>(m, "Server")
        .def(py::init<>());
        
    py::class_<node_t>(m, "Node")
        .def(py::init<>());

    py::class_<node_local_update_t>(m, "NodeLocalUpdate")
        .def(py::init<>());
        
    py::class_<srv_dropout_list_t>(m, "SrvDropoutList")
        .def(py::init<>());
        
    py::class_<node_shares_msg_t>(m, "NodeSharesMsg")
        .def(py::init<>())
        .def_readonly("item_cnt", &node_shares_msg_t::item_cnt); 

    py::class_<node_set_t>(m, "NodeSet")
        .def(py::init<>())
        .def_readonly("node_count", &node_set_t::node_count)
        .def_property_readonly("ids", [](const node_set_t& set) {
            std::vector<int> ids;
            ids.reserve(set.node_count);
            for (int i = 0; i < set.node_count; i++) {
                ids.push_back(set.node_id[i]);
            }
            return ids;
        });

    m.def("ta_setup_protocol", [](int num_clients, int threshold, server_t& srv) {
        ta_setup_protocol(num_clients, threshold, &srv);
    }, "Setup the TA and Server");

    m.def("configure_complete_recovery_topology", [](int num_clients) {
        configure_complete_recovery_topology(num_clients);
    }, "Configure the default complete recovery graph");

    m.def("configure_recovery_topology", &py_configure_recovery_topology,
          "Configure helper-to-target recovery edges before TA setup");

    m.def("client_setup", [](node_t& node, int id) {
        client_setup(&node, id);
    }, "Setup a Client Node");

    m.def("client_mask_update", &py_client_mask_update, "Generate an obfuscated update from numpy weights");

    m.def("server_receive_update", [](server_t& srv, node_local_update_t& msg) {
        server_receive_update(&srv, &msg);
    }, "Feed an update into the server");

    m.def("server_broadcast_dropouts", [](server_t& srv) {
        srv_dropout_list_t drop_msg;
        node_set_t dropouts;
        server_broadcast_dropouts(&srv, &drop_msg, &dropouts);
        return py::make_tuple(drop_msg, dropouts);
    }, "Get the signed dropout list and plaintext dropout set from the server");

    m.def("client_compute_shares", [](node_t& node, srv_dropout_list_t& in_drop_msg) {
        node_shares_msg_t out_msg;
        client_compute_shares(&node, &in_drop_msg, &out_msg);
        return out_msg;
    }, "Client computes recovery shares based on the server's dropout list");

    m.def("server_receive_shares", [](server_t& srv, node_shares_msg_t& msg) {
        server_receive_shares(&srv, &msg);
    }, "Feed recovery shares to the server");

    m.def("server_aggregate_updates", &py_server_aggregate_updates, "Finalize the round and return the cleartext NumPy array");

    // ------ Consistency check ------
    py::class_<node_cc_msg_t>(m, "NodeCCMsg")
        .def(py::init<>());

    py::class_<srv_cc_result_t>(m, "SrvCCResult")
        .def(py::init<>());

    m.def("client_compute_cc_value", [](node_t& node, srv_dropout_list_t& in_drop_msg) {
        node_cc_msg_t out_msg;
        client_compute_cc_value(&node, &in_drop_msg, &out_msg);
        return out_msg;
    }, "Client hashes the announced dropout list and computes w_j = h*y_j + z_j");

    m.def("server_receive_cc_value", [](server_t& srv, node_cc_msg_t& msg) {
        server_receive_cc_value_msg(&srv, &msg);
    }, "Feed a node's consistency check value to the server");

    m.def("server_finalize_cc_result", [](server_t& srv) {
        srv_cc_result_t result;
        bool ready = server_finalize_cc_result(&srv, &result);
        return py::make_tuple(ready, result);
    }, "Interpolate W = h*Scc1 + Scc2 once enough w_j values are collected");

    m.def("client_verify_cc_result", [](node_t& node, srv_dropout_list_t& in_drop_msg, srv_cc_result_t& result_msg) {
        return client_verify_cc_result(&node, &in_drop_msg, &result_msg);
    }, "Client verifies G^W == G1^h * G2; false means the round must be aborted");
}

