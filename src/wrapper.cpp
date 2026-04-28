#include <pybind11/pybind11.h>
#include <pybind11/numpy.h>
#include <pybind11/stl.h>
#include "heversa_api.h"

namespace py = pybind11;

node_local_update_t py_client_mask_update(node_t& node, py::array_t<uint32_t> weights) {
    py::buffer_info buf = weights.request();
    
    if (buf.size != UPDATE_LEN) {
        throw std::runtime_error("Weights array must have exactly UPDATE_LEN elements.");
    }
    
    uint32_t* ptr = static_cast<uint32_t*>(buf.ptr);
    node_local_update_t out_msg;
    
    client_mask_update(&node, ptr, &out_msg);
    return out_msg;
}

py::array_t<uint32_t> py_server_aggregate_updates(server_t& srv) {
    auto result = py::array_t<uint32_t>(UPDATE_LEN);
    py::buffer_info buf = result.request();
    
    uint32_t* ptr = static_cast<uint32_t*>(buf.ptr);
    
    server_aggregate_updates(&srv, ptr);
    return result;
}

PYBIND11_MODULE(heversa, m) {
    m.doc() = "Python bindings for the HeVerSa secure aggregation protocol";

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
        .def_readonly("node_count", &node_set_t::node_count);

    m.def("ta_setup_protocol", [](int num_clients, int threshold, server_t& srv) {
        ta_setup_protocol(num_clients, threshold, &srv);
    }, "Setup the TA and Server");

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
}