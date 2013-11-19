/*
 * fib_list.cc
 *
 *  Created on: Sep 20, 2013
 *      Author: gautier
 */

#include <click/config.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>
#include "fib_list.hh"

CLICK_DECLS

FIB_List::FIB_List(){cout << "Creating FIB_List" << endl;}
FIB_List::~FIB_List(){
	list_FIB.clear();
	gen.clear();
}



int FIB_List::configure(Vector<String> &conf, ErrorHandler *errh) {
	return 0;
}

void FIB_List::push(int, Packet *p){
	if(p == NULL){
		cout << "Null packet" << endl;
		p->kill();
		return;
	}
	cout << "Push function" << endl;
	click_ip6 *test = (click_ip6 *) malloc(sizeof(p->ip6_header()));
	cout << "memory allocated" << endl;
	memcpy(test, p->ip6_header(), sizeof(p->ip6_header()));
	cout << "memory copied" << endl;
	click_ip6 *header = const_cast<click_ip6 *>(p->ip6_header());
	cout << "1 ";
	IP6Address dst = IP6Address(header->ip6_dst);
	cout << "2 ";
	IP6Address src = IP6Address(header->ip6_src);
	cout << "3 end of danger zone" << endl;
	IP6Address gw;
	uint32_t flow_label = header->ip6_flow;

	int index;
	if(lookup(dst, src, flow_label, gw, index)){
		if (gw != IP6Address()) {
			SET_DST_IP6_ANNO(p, IP6Address(gw));
		}
		output(index).push(p);
	}else{
		p->kill();
	}
	cout << "End of Push" << endl;
}

bool FIB_List::lookup(const IP6Address &dst, const IP6Address &src, const uint32_t flow_label,
		  	  	  IP6Address &gw, int &index) const{
	bool found = false;
	//We first look if the src addr is covered by one of the configured prefix
	int i, best = 0;
	bool found_spec_FIB = false;
	for(i=0; i<list_FIB.size(); i++){
		if (src.matches_prefix(list_FIB[i].src, list_FIB[i].mask)) {
			if (found_spec_FIB){
				if (found_spec_FIB && list_FIB[i].mask.mask_as_specific(list_FIB[best].mask))
					best = i;
			}else{
				best = i;
				found_spec_FIB = true;
			}
		}
	}
	if(! found_spec_FIB){
		//We just look in the general FIB
		IP6Address mask = IP6Address();
		found = FIB_List::gen.lookup(dst, flow_label, gw, index, mask);
	}else{
		//We look in both FIB (the general one + the prefix one) see Baker's draft
		IP6Address mask1 = IP6Address(),
					mask2 = IP6Address();
		int index1, index2;
		found = (FIB_List::gen.lookup(dst, flow_label, gw, index1, mask1)
					| list_FIB[best].fib->lookup(dst, flow_label, gw, index2, mask2));
		//We select the most specific route
		if(mask1.mask_as_specific(mask2)){
			index = index1;
		}else{
			index = index2;
		}
	}
	return found;
}

void FIB_List::add(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label, const IP6Address &gw, int index){
	//Fist we check if the src addr is specified
	if(operator==(src_mask, IP6Address())){
		//It is not
		cout << "Adding in the general table" << endl;
		FIB_List::gen.add(dst, dst_mask, flow_label, gw, index);
	}else{
		//We look if there is already a FIB linked to this source prefix
		bool found = false;
		int i;
		for(i=0; i<list_FIB.size(); i++){
			if(list_FIB[i].used){
				if(src.matches_prefix(list_FIB[i].src, list_FIB[i].mask)){
					if (list_FIB[i].mask == src_mask){
						found = true;
						break;
					}
				}
			}
		}
		if(!found){
			//We have to create a new FIB
			cout << "Creating new FIB" << endl;
			FIB f;
			f.add(dst, dst_mask, flow_label, gw, index);

			//We link a source prefix to the FIB and add it to list_FIB
			Spec_FIB e;
			e.mask=src_mask;
			e.src=src;
			e.fib=&f;
			e.used=true;

			//We insert it in list_FIB
			bool inserted = false;
			for(int i=0; i<list_FIB.size(); i++){
				if(!list_FIB[i].used){
					//The position is empty, we can add the FIB here
					list_FIB[i] = e;
					inserted=true;
					break;
				}
			}
			if(!inserted){
				//We put it at the end of the vector
				list_FIB.push_back(e);
			}

		}else{	//There is a FIB with the same source prefix
			cout << "Inserting route in special FIB" << endl;
			list_FIB[i].fib->add(dst, dst_mask, flow_label, gw, index);
		}

	}
}

void FIB_List::del(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label)
{
/*
 * Looks if there is a special FIB with the same source prefix
 * If not delete in the general FIB
 * If we delete inside a special FIB and it makes it empty, we remove the FIB
 */
	for(int i=0; i<list_FIB.size(); i++){
		if((operator==(list_FIB[i].mask,src_mask)) && src.matches_prefix(list_FIB[i].src, list_FIB[i].mask)){
			list_FIB[i].fib->del(dst, dst_mask, flow_label);
			if(list_FIB[i].fib->root.children.size() == 0)
				//We remove the entire FIB
				list_FIB[i].used=false;
			return;
		}
	}

	//If we reach this point, it means there was no FIB with the same source prefix
	//Therefore we must delete the route in the general FIB
	gen.del(dst, dst_mask, flow_label);

}

void FIB_List::deal_with_ambiguities(const IP6Address &dst, const IP6Address &dst_mask, const IP6Address &src,
		  	  const IP6Address &src_mask, const uint32_t flow_label, const IP6Address &gw, int index){
	//This function deals with the problem of having two routes which intersection is not NULL
	//We create a third route giving the priority to the destination
	cout << "Dealing with ambiguities" << endl;
	cout << "list_FIB.size()=" << list_FIB.size() << endl;
	for(int i=0; i<list_FIB.size(); i++){
		if((list_FIB[i].used && src_mask.mask_as_specific(list_FIB[i].mask))&&(src.matches_prefix(list_FIB[i].src, list_FIB[i].mask))){
			//We have to add a new rule in this FIB
			if(!operator==(src_mask, list_FIB[i].mask)) //Otherwise we would add the rule twice
				list_FIB[i].fib->add(dst, dst_mask, flow_label, gw, index);
		}
	}
}

IP6Address
IP6Address::make_prefix(int prefix_len)
{
    assert(prefix_len >= 0 && prefix_len <= 128);
    IP6Address a = IP6Address::uninitialized_t();
    int i;
    for (i = 0; i < 4 && prefix_len >= 32; ++i, prefix_len -= 32)
	a._addr.s6_addr32[i] = 0xFFFFFFFFU;
    if (i < 4 && prefix_len > 0) {
	a._addr.s6_addr32[i] = htonl(0xFFFFFFFFU << (32 - prefix_len));
	++i;
    }
    for (; i < 4; ++i)
	a._addr.s6_addr32[i] = 0;
    return a;
}

int FIB_List::add_route_handler(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    cout << "adding route:" << endl;
	FIB_List *r = static_cast<FIB_List *>(e); //used at the end

    Vector<String> words;
    cp_spacevec(conf, words);

    unsigned char *addr = (unsigned char *) malloc(sizeof(click_in6_addr));

    click_in6_addr dst_copy, src_copy, gw_copy;
    int ok, port;
    uint32_t flow_label;
    ok=1;

    //We have to interpret the arguments sent from Quagga

    /* First, the destination prefix */
    memcpy(addr, words.at(0).c_str(), strlen(words.at(0).c_str()));
    IP6Address dst = IP6Address(addr);

    /* The length of the prefix */
    char *p_len = (char *) malloc(words.at(1).length());
    strcpy(p_len, words.at(1).c_str());
    IP6Address dst_mask = IP6Address::make_prefix(atoi(p_len));

    /* The source prefix */
    memcpy(addr, words.at(2).c_str(), strlen(words.at(2).c_str()));
    IP6Address src = IP6Address(addr);

    /* The length of the prefix */
    strcpy(p_len, words.at(3).c_str());
    IP6Address src_mask = IP6Address::make_prefix(atoi(p_len));
    free(p_len);

    /* The fow label */
    char *flow =(char *) malloc(words.at(4).length());
    strcpy(flow, words.at(4).c_str());
    flow_label = strtoul(flow, NULL, 0);
    free(flow);

    /* The gateway */
    memcpy(addr, words.at(5).c_str(), strlen(words.at(5).c_str()));
    IP6Address gw = IP6Address(addr);

    /* The port number */
    char *port_c = (char *) malloc(words.at(6).length());
    strcpy(port_c, words.at(6).c_str());
    port = atoi(port_c);
    free(port_c);

    if ((port < 0 || port >= r->noutputs())){
    	cout << "output out of range" << endl;
        ok = errh->error("output port out of range");
    }else{
        r->add(dst, dst_mask, src, src_mask, flow_label, gw, port);
        r->deal_with_ambiguities(dst, dst_mask, src, src_mask, flow_label, gw, port);
    }
    free(addr);
    return ok;
}

int FIB_List::remove_route_handler(const String &conf, Element *e, void *, ErrorHandler *errh)
{
    FIB_List *r = static_cast<FIB_List *>(e);

    Vector<String> words;
    cp_spacevec(conf, words);

    uint32_t flow_label;
    int port;

    unsigned char *addr = (unsigned char *) malloc(sizeof(click_in6_addr));

    /* dst pref */
    memcpy(addr, words.at(0).c_str(), strlen(words.at(0).c_str()));
	IP6Address dst = IP6Address(addr);

	/* The length of the prefix */
	char *p_len = (char *) malloc(words.at(1).length());
	strcpy(p_len, words.at(1).c_str());
	cout << p_len << endl;
	IP6Address dst_mask = IP6Address::make_prefix(atoi(p_len));

	/* The source prefix */
	memcpy(addr, words.at(2).c_str(), strlen(words.at(2).c_str()));
	IP6Address src = IP6Address(addr);

	/* The length of the prefix */
	strcpy(p_len, words.at(3).c_str());
	IP6Address src_mask = IP6Address::make_prefix(atoi(p_len));
	free(p_len);

	/* The fow label */
	char *flow =(char *) malloc(words.at(4).length());
	strcpy(flow, words.at(4).c_str());
	flow_label = strtoul(flow, NULL, 0);
	free(flow);

    r->del(dst, dst_mask, src, src_mask, flow_label);
    return 0;
}

int FIB_List::ctrl_handler(const String &conf_in, Element *e, void *thunk, ErrorHandler *errh)
{
    String conf = conf_in;
    String first_word = cp_shift_spacevec(conf);
    if (first_word == "add")
    	return add_route_handler(conf, e , thunk, errh);
    else if (first_word == "del")
    	return remove_route_handler(conf, e, thunk, errh);
    else
    	return errh->error("bad command, should be `add' or `del'");
}

void FIB_List::add_handlers()
{

    add_write_handler("add", add_route_handler, 0);
    add_write_handler("del", remove_route_handler, 0);
    add_write_handler("ctrl", ctrl_handler, 0);	/* Really necessary? */
    add_read_handler("table", table_handler, 0);
    cout << "Handlers added" << endl;

}

String FIB_List::table_handler(Element *e, void *)
{
    FIB_List *r = static_cast<FIB_List*>(e);
    return r->dump();
}


CLICK_ENDDECLS
EXPORT_ELEMENT(FIB_List)
ELEMENT_REQUIRES(userlevel|ip6)
