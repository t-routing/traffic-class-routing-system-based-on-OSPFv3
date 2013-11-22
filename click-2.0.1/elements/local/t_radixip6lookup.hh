#ifndef CLICK_T_RADIXIP6LOOKUP_HH
#define CLICK_T_RADIXIP6LOOKUP_HH
#include <click/glue.hh>
#include <click/element.hh>
#include "t_ip6routetable.hh"
CLICK_DECLS


class T_RadixIP6Lookup : public T_IP6RouteTable { public:

    T_RadixIP6Lookup();
    ~T_RadixIP6Lookup();

    const char *class_name() const		{ return "T_RadixIP6Lookup"; }
    const char *port_count() const		{ return "1/-"; }
    const char *processing() const		{ return PUSH; }

    void cleanup(CleanupStage);

    int add_route(const T_IP6Route&, bool, T_IP6Route*, ErrorHandler *);
    int remove_route(const T_IP6Route&, T_IP6Route*, ErrorHandler *);
    int lookup_route(IP6Address, IP6Address, IP6Address&) const;    //区别于T_IPRouteTable中的lookup_route
    //String dump_routes();

  private:

		class Radix;

		// Simple routing table
		Vector<T_IP6Route> _v;
		int _vfree;

		int _default_key;
		Radix *_radix;

	};


CLICK_ENDDECLS
#endif

