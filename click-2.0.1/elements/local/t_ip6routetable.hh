#ifndef CLICK_T_IP6ROUTETABLE_HH
#define CLICK_T_IP6ROUTETABLE_HH
#include <click/ip6address.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/element.hh>
CLICK_DECLS

struct T_IP6Route {
    IP6Address addr_d;
    IP6Address mask_d;
    IP6Address addr_s;
    IP6Address mask_s;
    IP6Address gw;
    int32_t port;
    int32_t extra;

    T_IP6Route()			: port(-1) { }
    T_IP6Route(IP6Address a_d, IP6Address m_d, IP6Address a_s, IP6Address m_s, IP6Address g, int p)
				: addr_d(a_d), mask_d(m_d), addr_s(a_s), mask_s(m_s), gw(g), port(p) { }

    inline bool real() const	{ return port > (int32_t) -0x80000000; }
    //inline void kill()		{ addr_d.data32() = 0; mask_d.data32() = 0; addr_s.data32() = 0; mask_s.data32() = 0; port = -0x80000000; }
    inline bool contains(IP6Address a_d, IP6Address a_s) const;
    inline bool contains(const T_IP6Route& r) const;
    inline bool mask_as_specific(IP6Address m_d, IP6Address m_s) const;
    inline bool mask_as_specific(const T_IP6Route& r) const;
    inline bool match(const T_IP6Route& r) const;
    int prefix_len_d() const	{ return mask_d.mask_to_prefix_len(); }    //分为两个
	int prefix_len_s() const    { return mask_s.mask_to_prefix_len(); }

    //StringAccum &unparse(StringAccum&, bool tabs) const;
    //String unparse() const;
    //String unparse_addr_d() const	{ return addr_d.unparse_with_mask(mask_d); }
    //String unparse_addr_s() const	{ return addr_s.unparse_with_mask(mask_s); }
};

class T_IP6RouteTable : public Element { public:

    void* cast(const char*);
    int configure(Vector<String>&, ErrorHandler*);
    void add_handlers();

    virtual int add_route(const T_IP6Route& route, bool allow_replace, T_IP6Route* replaced_route, ErrorHandler* errh);
    virtual int remove_route(const T_IP6Route& route, T_IP6Route* removed_route, ErrorHandler* errh);
    virtual int lookup_route(IP6Address addr_d, IP6Address addr_s, IP6Address& gw) const = 0;     //packet没有src_ip_anno
    virtual String dump_routes();

    void push(int port, Packet* p);

    static int add_route_handler(const String&, Element*, void*, ErrorHandler*);
    static int remove_route_handler(const String&, Element*, void*, ErrorHandler*);
    static int ctrl_handler(const String&, Element*, void*, ErrorHandler*);
    static int lookup_handler(int operation, String&, Element*, const Handler*, ErrorHandler*);  //查找handler
    static String table_handler(Element*, void*);

  private:

    enum { CMD_ADD, CMD_SET, CMD_REMOVE };
    int run_command(int command, const String &, Vector<T_IP6Route>* old_routes, ErrorHandler*);

};

/*inline StringAccum&
operator<<(StringAccum& sa, const T_IP6Route& route)
{
    return route.unparse(sa, false);
}*/

inline bool
T_IP6Route::contains(IP6Address a_d, IP6Address a_s) const
{
    return a_d.matches_prefix(addr_d, mask_d) && a_s.matches_prefix(addr_s, mask_s);
}

inline bool
T_IP6Route::contains(const T_IP6Route& r) const
{
    return (r.addr_d.matches_prefix(addr_d, mask_d) && r.mask_d.mask_as_specific(mask_d)) && (r.addr_s.matches_prefix(addr_s, mask_s) && r.mask_s.mask_as_specific(mask_s));
}

inline bool
T_IP6Route::mask_as_specific(IP6Address m_d, IP6Address m_s) const
{
    return mask_d.mask_as_specific(m_d) && mask_s.mask_as_specific(m_s);
}

inline bool
T_IP6Route::mask_as_specific(const T_IP6Route& r) const
{
    return mask_d.mask_as_specific(r.mask_d) && mask_s.mask_as_specific(r.mask_s);
}

inline bool
T_IP6Route::match(const T_IP6Route& r) const
{
    return addr_d == r.addr_d && mask_d == r.mask_d && addr_s == r.addr_s && mask_s == r.mask_s
	&& (port < 0 || (gw == r.gw && port == r.port));
}

CLICK_ENDDECLS
#endif

