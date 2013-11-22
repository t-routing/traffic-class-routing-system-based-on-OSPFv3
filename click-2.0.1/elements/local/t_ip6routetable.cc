#include <click/config.h>
#include <click/ip6address.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/router.hh>
#include "t_ip6routetable.hh"
CLICK_DECLS

bool
cp_ip6_route(String s, T_IP6Route *r_store, bool remove_route, Element *context)
{
    T_IP6Route r;
    //if (!IP6PrefixArg(true).parse(cp_shift_spacevec(s), r.addr_d, r.mask_d, context))
      	//return false;
    r.addr_d &= r.mask_d;
	r.addr_s &= r.mask_s;

    String word = cp_shift_spacevec(s);
    //if (word == "-")
	/* null gateway; do nothing */;
    //else if (IP6AddressArg().parse(word, r.gw, context))
	/* do nothing */;
    //else
	//goto two_words;

    word = cp_shift_spacevec(s);
  two_words:
    if (IntArg().parse(word, r.port) || (!word && remove_route))
	if (!cp_shift_spacevec(s)) { // nothing left
	    *r_store = r;
	    return true;
	}

    return false;
}

/*StringAccum&
T_IP6Route::unparse(StringAccum& sa, bool tabs) const
{
    int l = sa.length();
    char tab = (tabs ? '\t' : ' ');
    //sa << addr_d.unparse_with_mask(mask_d) << tab;
    if (sa.length() < l + 17 && tabs)
	sa << '\t';
    l = sa.length();
    if (gw)
	sa << gw << tab;
    else
	sa << '-' << tab;
    if (sa.length() < l + 9 && tabs)
	sa << '\t';
    if (!real())
	sa << "-1";
    else
	sa << port;
    return sa;
}

String
T_IP6Route::unparse() const
{
    StringAccum sa;
    sa << *this;
    return sa.take_string();
}*/


void *
T_IP6RouteTable::cast(const char *name)
{
    if (strcmp(name, "T_IP6RouteTable") == 0)
	return (void *)this;
    else
	return Element::cast(name);
}

//need specify configure format
int
T_IP6RouteTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int r = 0, r1, eexist = 0;
    T_IP6Route route;
    for (int i = 0; i < conf.size(); i++) {
	if (!cp_ip6_route(conf[i], &route, false, this)) {
	    errh->error("argument %d should be %<ADDR/MASK [GATEWAY] OUTPUT%>", i+1);
	    r = -EINVAL;
	} else if (route.port < 0 || route.port >= noutputs()) {
	    errh->error("argument %d bad OUTPUT", i+1);
	    r = -EINVAL;
	} else if ((r1 = add_route(route, false, 0, errh)) < 0) {
	    if (r1 == -EEXIST)
		++eexist;
	    else
		r = r1;
	}
    }
    if (eexist)
	errh->warning("%d %s replaced by later versions", eexist, eexist > 1 ? "routes" : "route");
    return r;
}

int
T_IP6RouteTable::add_route(const T_IP6Route&, bool, T_IP6Route*, ErrorHandler *errh)

{
    // by default, cannot add routes
    return errh->error("cannot add routes to this routing table");
}

int
T_IP6RouteTable::remove_route(const T_IP6Route&, T_IP6Route*, ErrorHandler *errh)

{
    // by default, cannot remove routes
    return errh->error("cannot delete routes from this routing table");
}

int
T_IP6RouteTable::lookup_route(IP6Address, IP6Address, IP6Address&) const
{
    return -1;			// by default, route lookups fail
}

String
T_IP6RouteTable::dump_routes()
{
    return String();
}


void
T_IP6RouteTable::push(int, Packet *p)
{
    IP6Address gw;

	click_ip6 *test = (click_ip6 *) malloc(sizeof(p->ip6_header()));

	memcpy(test, p->ip6_header(), sizeof(p->ip6_header()));

	click_ip6 *header = const_cast<click_ip6 *>(p->ip6_header());

	IP6Address dst = IP6Address(header->ip6_dst);

	IP6Address src = IP6Address(header->ip6_src);

    int port = lookup_route(dst, src, gw);                    //no src!!!
    if (port >= 0) {
	assert(port < noutputs());
	//if (gw)
	    //p->set_dst_ip6_anno(gw);
	output(port).push(p);
    } else {
	p->kill();
    }

}


int
T_IP6RouteTable::run_command(int command, const String &str, Vector<T_IP6Route>* old_routes, ErrorHandler *errh)
{
    T_IP6Route route, old_route;
    if (!cp_ip6_route(str, &route, command == CMD_REMOVE, this))
	return errh->error("expected %<ADDR/MASK [GATEWAY%s%>", (command == CMD_REMOVE ? " OUTPUT]" : "] OUTPUT"));
    else if (route.port < (command == CMD_REMOVE ? -1 : 0)
	     || route.port >= noutputs())
	return errh->error("bad OUTPUT");

    int r, before = errh->nerrors();
    if (command == CMD_ADD)
	r = add_route(route, false, &old_route, errh);
    else if (command == CMD_SET)
	r = add_route(route, true, &old_route, errh);
    else
	r = remove_route(route, &old_route, errh);

    // save old route if in a transaction
    if (r >= 0 && old_routes) {
	if (old_route.port < 0) { // must come from add_route
	    old_route = route;
	    old_route.extra = CMD_ADD;
	} else
	    old_route.extra = command;
	old_routes->push_back(old_route);
    }

    // report common errors
    /*if (r == -EEXIST && errh->nerrors() == before)
	errh->error("conflict with existing route %<%s%>", old_route.unparse().c_str());
    if (r == -ENOENT && errh->nerrors() == before)
	errh->error("route %<%s%> not found", route.unparse().c_str());
    if (r == -ENOMEM && errh->nerrors() == before)
	errh->error("no memory to store route %<%s%>", route.unparse().c_str());*/
    return r;
}


int
T_IP6RouteTable::add_route_handler(const String &conf, Element *e, void *thunk, ErrorHandler *errh)
{
    T_IP6RouteTable *table = static_cast<T_IP6RouteTable *>(e);
    return table->run_command((thunk ? CMD_SET : CMD_ADD), conf, 0, errh);
}

int
T_IP6RouteTable::remove_route_handler(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    T_IP6RouteTable *table = static_cast<T_IP6RouteTable *>(e);
    return table->run_command(CMD_REMOVE, conf, 0, errh);
}

int
T_IP6RouteTable::ctrl_handler(const String &conf_in, Element *e, void *, ErrorHandler *errh)
{
    T_IP6RouteTable *table = static_cast<T_IP6RouteTable *>(e);
    String conf = cp_uncomment(conf_in);
    const char* s = conf.begin(), *end = conf.end();

    Vector<T_IP6Route> old_routes;
    int r = 0;

    while (s < end) {
	const char* nl = find(s, end, '\n');
	String line = conf.substring(s, nl);

	String first_word = cp_shift_spacevec(line);
	int command;
	if (first_word == "add")
	    command = CMD_ADD;
	else if (first_word == "remove")
	    command = CMD_REMOVE;
	else if (first_word == "set")
	    command = CMD_SET;
	else if (!first_word)
	    continue;
	else {
	    r = errh->error("bad command %<%#s%>", first_word.c_str());
	    goto rollback;
	}

	if ((r = table->run_command(command, line, &old_routes, errh)) < 0)
	    goto rollback;

	s = nl + 1;
    }
    return 0;

  rollback:
    while (old_routes.size()) {
	const T_IP6Route& rt = old_routes.back();
	if (rt.extra == CMD_REMOVE)
	    table->add_route(rt, false, 0, errh);
	else if (rt.extra == CMD_ADD)
	    table->remove_route(rt, 0, errh);
	else
	    table->add_route(rt, true, 0, errh);
	old_routes.pop_back();
    }
    return r;
}

String
T_IP6RouteTable::table_handler(Element *e, void *)
{
    T_IP6RouteTable *r = static_cast<T_IP6RouteTable*>(e);
    return r->dump_routes();
}

/*int
T_IP6RouteTable::lookup_handler(int, String& s, Element* e, const Handler*, ErrorHandler* errh)
{
    T_IP6RouteTable *table = static_cast<T_IP6RouteTable*>(e);
    IP6Address a;
    if (IP6AddressArg().parse(s, a, table)) {
	IP6Address gw;
	int port = table->lookup_route(a, 0, gw);
	if (gw)
	    s = String(port) + " " + gw.unparse();
	else
	    s = String(port);
	return 0;
    } else
	return errh->error("expected IP address");
}*/

void
T_IP6RouteTable::add_handlers()
{
    add_write_handler("add", add_route_handler, 0);
    add_write_handler("set", add_route_handler, 1);
    add_write_handler("remove", remove_route_handler);
    add_write_handler("ctrl", ctrl_handler);
    add_read_handler("table", table_handler, 0, Handler::EXPENSIVE);
    //set_handler("lookup", Handler::OP_READ | Handler::READ_PARAM, lookup_handler);
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(T_IP6RouteTable)

