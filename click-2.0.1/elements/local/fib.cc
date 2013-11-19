/*
 * fib.cc
 *
 *  Created on: Sep 20, 2013
 *      Author: gautier
 */

#include <click/config.h>
#include <clicknet/ip6.h>
#include "fib.hh"

CLICK_DECLS

FIB::FIB()
{
	this->root.valid = false;
	//this->root.children = new vector<Node*>;
	/*for(int i=0; i<DEFAULT_SIZE; i++){
		v[i]->used = false;
		v[i]->valid= false;
	}*/

}

FIB::~FIB()
{
}


bool FIB::lookup(const IP6Address &dst, const uint32_t flow_label, IP6Address &gw,
				int &index, IP6Address &dst_mask) const{
	bool found = false;
	if(root.valid){
		found = true;
		gw = root._gw;
		index = root._index;
	}
	int best=-1;
	for(int i=0; i<root.children.size(); i++){
		if (root.children[i]->used && dst.matches_prefix(root.children[i]->_addr, root.children[i]->_mask)) {
		      if (best < 0 || root.children[i]->_mask.mask_as_specific(root.children[best]->_mask))
		        best = i;
		}
	}
	if(best<0)	//It means there are no destination prefix that matches dst
		return found;
	else{
		//We look for the flow label and if we do not find any, we check if the current node has a valid gw
		bool found_fl = false;
		for(int i=0; i<root.children[best]->children.size(); i++){
			if(root.children[best]->children[i]->used && root.children[best]->children[i]->_flow_label==flow_label){
				found_fl = true;
				gw = root.children[best]->children[i]->_gw;
				dst_mask = root.children[best]->_mask;
				index = root.children[best]->_index;
				return found;
			}
		}
		//If we reach this point, it means we have not found any specific flow label
		if(root.children[best]->valid){
			gw = root.children[best]->_gw;
			dst_mask = root.children[best]->_mask;
			index = root.children[best]->_index;
		}
	}
	return found;
}

void FIB::add(const IP6Address &dst, const IP6Address &dst_mask, const uint32_t flow_label,
		  	  const IP6Address &gw, const int index){
	if(operator==(dst_mask, IP6Address())){	//It's a default destination address
		//As the destination has priority over the flow label we do:
			root._gw = gw;
			root.valid = true;
			root._index = index;
	}else{	//We check if there is already a child with the same dst addr
		int last_unused = -1;
		for(int i=0; i<root.children.size(); i++){
			cout << "inside for" << endl;
			if(root.children[i]->used){
				if(operator==(root.children[i]->_addr, dst) && operator==(root.children[i]->_mask, dst_mask)){
					if(flow_label == 0){
						root.children[i]->_gw=gw;
						root.children[i]->valid=true;
						root._index=index;
					}else{
						int last_unused2 = -1;
						for(int j=0; j<root.children[i]->children.size(); j++){
							if(root.children[i]->children[j]->_flow_label==flow_label){
								root.children[i]->children[j]->_gw=gw;
								root.children[i]->children[j]->used=true;
								root._index=index;
								return;
							}else if(root.children[i]->children[j]->used==false)
								last_unused2 = j;
						}
						//If we are here, it means there is no flow label for this node yet.
						if(last_unused2 != -1){
							root.children[i]->children[last_unused2]->used=true;
							root.children[i]->children[last_unused2]->_gw=gw;
							root.children[i]->children[last_unused2]->_index=index;
						}else{
							Leaf l;
							l._flow_label=flow_label;
							l._gw=gw;
							l.used=true;
							l._index=index;
							root.children[i]->children.push_back(&l);
						}
					}
					return;
				}
			}else
				last_unused = i;
		}//Here, we have look through all the children of the root and none has the same destination address
		if(last_unused != -1){
			cout << "inserting in unused space" << endl;
			root.children[last_unused]->_addr=dst;
			root.children[last_unused]->_mask=dst_mask;
			root.children[last_unused]->used=true;
			root.children[last_unused]->_index=index;
			if(flow_label!=0){
				Leaf l;
				l._flow_label=flow_label;
				l._gw=gw;
				l.used=true;
				l._index=index;
				root.children[last_unused]->children.push_back(&l);
			}else{
				root.children[last_unused]->_gw=gw;
				root.children[last_unused]->valid=true;
				root.children[last_unused]->_index=index;
			}

		}else{
			cout << "Creating node" << endl;;
			//We have to create a new node
			Node n;
			n._addr=dst;
			n._mask=dst_mask;
			n.used=true;
			cout << "Node created" << endl;
			if(flow_label==0){
				cout << "flowlabel null" << endl;
				n._gw=gw;
				n.valid=true;
				n._index=index;
			}else{
				cout << "creating leaf" << endl;
				Leaf l;
				l._flow_label=flow_label;
				l._gw=gw;
				l.used=true;
				l._index=index;
				n.children.push_back(&l);
				cout << "pushed" << endl;
			}
			cout << "pushing node" << endl;
			root.children.push_back(&n);
			cout << "node pushed" << endl;
		}
	}

}

void FIB::del(const IP6Address &dst, const IP6Address &dst_mask, const uint32_t flow_label){
	if(operator==(dst_mask, IP6Address())){
		root.valid=false;
	}else{
		for(int i=0; i<root.children.size(); i++){
			if(operator==(dst, root.children[i]->_addr) && operator==(dst_mask, root.children[i]->_mask)){
				if(flow_label == 0)
					root.children[i]->valid=false;
				else{
					for(int j=0; j<root.children[i]->children.size(); j++){
						if(root.children[i]->children[j]->_flow_label==flow_label)
							root.children[i]->children[j]->used=false;
					}
				}
			}
		}
	}
}


CLICK_ENDDECLS
ELEMENT_PROVIDES(FIB)
ELEMENT_REQUIRES(userlevel|ip6)
//ELEMENT_LIBS(-L/usr/local/Cellar/boost/1.54.0/ -linclude)

