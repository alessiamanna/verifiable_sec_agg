#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/numpy.h>
#include <vector>

#include "node.h"
#include "server.h"
#include "ta.h"
#include "msg_type.h"

namespace py = pybind11;
using namespace pybind11::literals;

struct PyIOHandler {
    py::object send_cb;
    py::object recv_cb;
    PyIOHandler(py::object s, py::object r) : send_cb(s), recv_cb(r) {}
};

prot_ret_t py_send_wrapper(void* obj, const uint8_t* data, size_t len) {
    auto* handler = static_cast<PyIOHandler*>(obj);
    try {
        py::gil_scoped_acquire acquire;
        handler->send_cb(py::bytes((const char*)data, len));
        return OK;
    } catch (py::error_already_set &e) {
        return ERROR;
    }
}

prot_ret_t py_recv_wrapper(void* obj, uint8_t* buff, size_t max_len, size_t* out_len) {
    auto* handler = static_cast<PyIOHandler*>(obj);
    try {
        py::gil_scoped_acquire acquire;
        py::bytes result = handler->recv_cb(max_len);
        std::string s = result;
        
        if (s.length() > max_len) return ERROR;
        memcpy(buff, s.data(), s.length());
        *out_len = s.length();
        return OK;
    } catch (py::error_already_set &e) {
        return ERROR;
    }
}

PYBIND11_MODULE(heversa, m) {
    m.doc() = "HeVerSa Secure Aggregation Protocol Bindings";

    py::class_<PyIOHandler>(m, "IOHandler")
        .def(py::init<py::object, py::object>());

    m.def("ta_setup_round", &ta_compute_offset, "N"_a, "K"_a, "base_idx"_a);
    m.def("ta_get_global_masks", [](server_t& srv, int N, uint32_t idx) {
        ta_send_global_masks(&srv, N, (puf_index_t)idx);
    });

    py::class_<node_t>(m, "Node")
        .def(py::init([](int id, py::object send_fn, py::object recv_fn) {
            auto* handler = new PyIOHandler(send_fn, recv_fn);
            node_t* n = new node_t();
            io_interface_t io = {handler, py_send_wrapper, py_recv_wrapper};
            node_setup(n, id, io);
            return n;
        }))

        .def("add_to_kj", [](node_t& n, int target_id) {
            node_set_add(&n.K_j, (node_id_t)target_id);
        })
        .def("set_input", [](node_t& n, py::array_t<uint32_t> weights) {
            auto r = weights.unchecked<1>();
            for(size_t i=0; i<UPDATE_LEN && i<r.shape(0); ++i) {
                n.data_update[i] = UInt128::from_uint32(r(i)); 
            }
        })
        .def("run_state", [](node_t& n) {
            run_node_state(&n);
        })
        .def_readonly("node_id", &node_t::node_id);

    py::class_<server_t>(m, "Server")
        .def(py::init([](int id, py::object send_fn, py::object recv_fn) {
            auto* handler = new PyIOHandler(send_fn, recv_fn);
            server_t* s = new server_t();
            io_interface_t io = {handler, py_send_wrapper, py_recv_wrapper};
            server_setup(s, id, io);
            return s;
        }))
        .def("run_state", &server_run_state)
        .def_static("db_init", &server_db_init)
        .def("get_result", [](server_t& s) {
            py::array_t<uint32_t> result(UPDATE_LEN);
            auto r = result.mutable_unchecked<1>();
            for (int i = 0; i < UPDATE_LEN; i++) {
                uint32_t val = 0;
                std::memcpy(&val, &s.clear_res[i], sizeof(uint32_t));
                r(i) = val;
            }
            return result;
        })
        
        .def_property_readonly("current_state_name", [](const server_t& s) {
            if (s.current_state == srv_state_wait_updates) return "WAIT_UPDATES";
            if (s.current_state == srv_state_req_shares) return "REQ_SHARES";
            if (s.current_state == srv_state_wait_recovery) return "WAIT_RECOVERY";
            if (s.current_state == srv_state_compute_global) return "COMPUTE_GLOBAL";
            return "UNKNOWN";
        });
}