#include <click/config.h>
#include <click/ip6address.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <math.h>
#include "t_radixip6lookup.hh"
CLICK_DECLS

class T_RadixIP6Lookup::Radix { public:

    static Radix *make_radix(int bitshift, int n);
    static void free_radix(Radix *r);

    int change_d(IP6Address addr_d, IP6Address mask_d, IP6Address addr_s, IP6Address mask_s, int key, bool set);
    int change_s(IP6Address addr_s, IP6Address mask_s, int key, bool set);

    void ip6tochar(IP6Address xx, char x[]){
        uint32_t *a = xx.data32();
        int i;
        char c0[8], c1[8], c2[8], c3[8];
        char b0[9], b1[9], b2[9], b3[9];
        memset(b0, '0', sizeof(b0));
        memset(b1, '0', sizeof(b1));
        memset(b2, '0', sizeof(b2));
        memset(b3, '0', sizeof(b3));
        int len0=0, len1=0, len2=0, len3=0;
        while (a[0]>0)
        {
            c0[len0++]=a[0]%2 + '0';
            a[0]/= 2;
        }
        for (i=0; i<len0; i++)
            b0[i+8-len0] = c0[len0-i-1];
        b0[8] = '\0';
        while (a[1]>0)
        {
            c1[len1++]=a[1]%2 + '0';
            a[1] /= 2;
        }
        for (i=0; i<len1; i++)
            b1[i+8-len1] = c1[len1-i-1];
        b1[8] = '\0';
        while (a[2]>0)
        {
            c2[len2++]=a[2]%2 + '0';
            a[2] /= 2;
        }
        for (i=0; i<len2; i++)
            b2[i+8-len2] = c2[len2-i-1];
        b2[8] = '\0';
        while (a[3]>0)
        {
            c3[len3++]=a[3]%2 + '0';
            a[3] /= 2;
        }
        for (i=0; i<len3; i++)
            b3[i+8-len3] = c3[len3-i-1];
        b3[8] = '\0';
        sprintf(x, "%s%s%s%s", b0, b1, b2, b3);
        x[32] = '\0';
    }

    inline int lookup(const Radix *r, int cur, IP6Address addr_d, IP6Address addr_s) {
    Radix *s_r;
    char dst[129], src[129];
    char temp[5];
    ip6tochar(addr_d, dst);
    ip6tochar(addr_s, src);
    while (r) {
        //int i1 = ( dst >> r->_bitshift) & (r->_n - 1);
        int i1 = 0;
        strncpy(temp, dst + 128-_bitshift, 4);
        temp[4] = '\0';
        for (int i=0; i<4; i++)
            i1 += (int)(temp[i]-'0') * (int)pow(2.0, (float)(3-i));
        const Child &c = r->_children[i1];
        r = c.child;
        s_r = c.src_radix;
        }

    while (s_r) {
        int i2 = 0;
        strncpy(temp, src + 128-_bitshift, 4);
        temp[4] = '\0';
        for (int i=0; i<4; i++)
            i2 += (int)(temp[i]-'0') * (int)pow(2.0, (float)(3-i));
        const Child &s_c = s_r->_children[i2];
        if (s_c.key)
            cur = s_c.key;
        s_r = s_c.child;
    }
	return cur;
    }

  private:

    int _bitshift;
    int _n;
    int _nchildren;

    struct Child {
	//bool _ifsrc;                   //if the radix node has src trie
	int key;
	Radix *child;
	Radix *src_radix;              //the root of src trie
    } _children[0];

    Radix()			{ }
    ~Radix()			{ }

    int &key_for(int i) {
		assert(i >= 2 && i < _n * 2);
		if (i >= _n)
	    	return _children[i - _n].key;
		else {
	    	int *x = reinterpret_cast<int *>(_children + _n);
	    	return x[i - 2];
		}
    }

    friend class T_RadixIP6Lookup;

};

T_RadixIP6Lookup::Radix*
T_RadixIP6Lookup::Radix::make_radix(int bitshift, int n)
{
    if (Radix* r = (Radix*) new unsigned char[sizeof(Radix) + n * sizeof(Child) + (n - 2) * sizeof(int)]) {
		r->_bitshift = bitshift;
		r->_n = n;
		r->_nchildren = 0;
		//r->_ifsrc = false;
		memset(r->_children, 0, n * sizeof(Child) + (n - 2) * sizeof(int));
		return r;
    } else
		return 0;
}

void
T_RadixIP6Lookup::Radix::free_radix(Radix* r)               //just for src trie
{
    if (r->_nchildren)
	for (int i = 0; i < r->_n; i++)
	    if (r->_children[i].child)
		free_radix(r->_children[i].child);
    delete[] (unsigned char *)r;
}

int
T_RadixIP6Lookup::Radix::change_d(IP6Address addr_d, IP6Address mask_d, IP6Address addr_s, IP6Address mask_s, int key, bool set)
{
    char dst_addr[129], dst_mask[129];
    char temp[5], temp1[5];
    ip6tochar(addr_d, dst_addr);
    ip6tochar(mask_d, dst_mask);
    int i1 = 0;
    strncpy(temp, dst_addr + 128-_bitshift, 4);
        temp[4] = '\0';
    for (int i=0; i<4; i++)
        i1 += (int)(temp[i]-'0') * (int)pow(2.0, (float)(3-i));
    // check if change only affects children
    //if ((unsigned char *)mask_d & ((1U << _bitshift) - 1)) {
    if (dst_mask[132-_bitshift] != '0'){
		if (!_children[i1].child && (_children[i1].child = make_radix(_bitshift - 4, 16)))
	    	++_nchildren;
		if (_children[i1].child)
	    	return _children[i1].child->change_d(addr_d, mask_d, addr_s, mask_s, key, set);
		else
	    	return 0;
    }

	//find in the dst trie
	//int nmask_d = _n - (((unsigned char *)mask_d >> _bitshift) & (_n - 1));
	int nmask_d = 0;
	strncpy(temp1, dst_mask + 128-_bitshift, 4);
        temp1[4] = '\0';
    for (int i=0; i<4; i++)
        nmask_d += (int)(temp1[i]-'0') * (int)pow(2.0, (float)(3-i));
	int num_prefix, count_prefix = 0;
	for (int x = nmask_d; x > 1; x /= 2)
		count_prefix ++;
	num_prefix = i1 / nmask_d + count_prefix * _n;

	int i2 = _n + i1;
    for (int x = nmask_d; x > 1; x /= 2)
		i2 /= 2;
	int replace_key_d = key_for(i2), prev_key_d = replace_key_d;
	if (prev_key_d && i2 > 3 && key_for(i2 / 2) == prev_key_d)
		prev_key_d = 0;

    if (!num_prefix && i2 > 3)
		num_prefix = key_for(i2 / 2);
    if (prev_key_d != num_prefix && !prev_key_d) {
		for (nmask_d = 1; i2 < _n * 2; i2 *= 2, nmask_d *= 2)
	    	for (int x = i2; x < i2 + nmask_d; ++x)
				if (key_for(x) == replace_key_d)
		    		key_for(x) = num_prefix;
    }
	for (int x = nmask_d; x > 1; x /= 2){
		i1 /= 2;
		i1 *= 2;
	}
	for (int x = i1; x < i1 + nmask_d; x++){
		if (key_for(x + _n) == num_prefix){
			if (!_children[x].src_radix)
				_children[x].src_radix = make_radix(24, 256);
			return _children[x].src_radix->change_s(addr_s, mask_s, key, set);
		}
	}
}

int T_RadixIP6Lookup::Radix::change_s(IP6Address addr_s, IP6Address mask_s, int key, bool set)
{
	//int i1 = ((unsigned char *)addr_s >> _bitshift) & (_n - 1);
    char src_addr[129], src_mask[129];
    char temp[5], temp1[5];
    ip6tochar(addr_s, src_addr);
    ip6tochar(mask_s, src_mask);
    int i1 = 0;
    strncpy(temp, src_addr + 128-_bitshift, 4);
        temp[4] = '\0';
    for (int i=0; i<4; i++)
        i1 += (int)(temp[i]-'0') * (int)pow(2.0, (float)(3-i));
    // check if change only affects children
    //if ((unsigned char *)mask_s & ((1U << _bitshift) - 1)) {
    if (src_mask[132-_bitshift] != '0'){
		if (!_children[i1].child && (_children[i1].child = make_radix(_bitshift - 4, 16)))
	    	++_nchildren;
		if (_children[i1].child)
	    	return _children[i1].child->change_s(addr_s, mask_s, key, set);
		else
	    	return 0;
    }

    // find current key in the src trie
    i1 = _n + i1;
    //int nmask_s = _n - (((unsigned char *)mask_s >> _bitshift) & (_n - 1));
    int nmask_s = 0;
	strncpy(temp1, src_mask + 128-_bitshift, 4);
        temp1[4] = '\0';
    for (int i=0; i<4; i++)
        nmask_s += (int)(temp1[i]-'0') * (int)pow(2.0, (float)(3-i));
    for (int x = nmask_s; x > 1; x /= 2)
		i1 /= 2;
    int replace_key = key_for(i1), prev_key = replace_key;
    if (prev_key && i1 > 3 && key_for(i1 / 2) == prev_key)
		prev_key = 0;

    // replace previous key with current key, if appropriate
    if (!key && i1 > 3)
		key = key_for(i1 / 2);
    if (prev_key != key && (!prev_key || set)) {
		for (nmask_s = 1; i1 < _n * 2; i1 *= 2, nmask_s *= 2)
	    	for (int x = i1; x < i1 + nmask_s; ++x)
				if (key_for(x) == replace_key)
		    		key_for(x) = key;
    }
    return prev_key;
}


T_RadixIP6Lookup::T_RadixIP6Lookup()
    : _vfree(-1), _default_key(0), _radix(Radix::make_radix(128, 16))
{
}

T_RadixIP6Lookup::~T_RadixIP6Lookup()
{
}


void
T_RadixIP6Lookup::cleanup(CleanupStage)
{
    _v.clear();
    Radix::free_radix(_radix);
    _radix = 0;
}


/*String
T_RadixIP6Lookup::dump_routes()
{
    StringAccum sa;
    for (int j = _vfree; j >= 0; j = _v[j].extra)
	_v[j].kill();
    for (int i = 0; i < _v.size(); i++)
	if (_v[i].real())
	    _v[i].unparse(sa, true) << '\n';
    return sa.take_string();
}*/


int
T_RadixIP6Lookup::add_route(const T_IP6Route &route, bool set, T_IP6Route *old_route, ErrorHandler *)
{
    int found = (_vfree < 0 ? _v.size() : _vfree), last_key;
    IP6Address addr_d = route.addr_d;
    IP6Address addr_s = route.addr_s;
    IP6Address mask_d = route.mask_d;
    IP6Address mask_s = route.mask_s;
    uint32_t *mask_dst = mask_d.data32();
    uint32_t *mask_src = mask_s.data32();
    if((mask_dst[0]||mask_dst[1]||mask_dst[2]||mask_dst[3]) && (mask_src[0]||mask_src[1]||mask_src[2]||mask_src[3]))
        last_key = _radix->change_d(addr_d, mask_d, addr_s, mask_s, found + 1, set);
    /*if (route.mask_d && route.mask_s) {
		uint32_t addr_d = ntohl(route.addr_d.addr());
		uint32_t mask_d = ntohl(route.mask_d.addr());
		uint32_t addr_s = ntohl(route.addr_s.addr());
		uint32_t mask_s = ntohl(route.mask_s.addr());
		last_key = _radix->change_d(addr_d, mask_d, addr_s, mask_s, found + 1, set);
    }*/
	else {
		last_key = _default_key;
		if (!last_key || set)
	    	_default_key = found + 1;
    }

    if (last_key && old_route)
		*old_route = _v[last_key - 1];
    if (last_key && !set)
		return -EEXIST;

    if (found == _v.size())
		_v.push_back(route);
    else {
		_vfree = _v[found].extra;
		_v[found] = route;
    }
    _v[found].extra = -1;

    if (last_key) {
		_v[last_key - 1].extra = _vfree;
		_vfree = last_key - 1;
    }

    return 0;
}

int
T_RadixIP6Lookup::remove_route(const T_IP6Route& route, T_IP6Route* old_route, ErrorHandler*)
{
    int last_key;
    IP6Address addr_d = route.addr_d;
    IP6Address addr_s = route.addr_s;
    IP6Address mask_d = route.mask_d;
    IP6Address mask_s = route.mask_s;
    /*if (route.mask_d && route.mask_s) {
	uint32_t addr_d = ntohl(route.addr_d.addr());
	uint32_t mask_d = ntohl(route.mask_d.addr());
	uint32_t addr_s = ntohl(route.addr_s.addr());
	uint32_t mask_s = ntohl(route.mask_s.addr());*/
	// NB: this will never actually make changes
    uint32_t *mask_dst = mask_d.data32();
    uint32_t *mask_src = mask_s.data32();
    if((mask_dst[0]||mask_dst[1]||mask_dst[2]||mask_dst[3]) && (mask_src[0]||mask_src[1]||mask_src[2]||mask_src[3]))
	last_key = _radix->change_d(addr_d, mask_d, addr_s, mask_s, 0, false);
    else
	last_key = _default_key;

    if (last_key && old_route)
	*old_route = _v[last_key - 1];
    if (!last_key || !route.match(_v[last_key - 1]))
	return -ENOENT;
    _v[last_key - 1].extra = _vfree;
    _vfree = last_key - 1;

    /*if (route.mask_d && route.mask_s) {
	uint32_t addr_d = ntohl(route.addr_d.addr());
	uint32_t mask_d = ntohl(route.mask_d.addr());
	uint32_t addr_s = ntohl(route.addr_s.addr());
	uint32_t mask_s = ntohl(route.mask_s.addr());*/
    if((mask_dst[0]||mask_dst[1]||mask_dst[2]||mask_dst[3]) && (mask_src[0]||mask_src[1]||mask_src[2]||mask_src[3]))
	(void) _radix->change_d(addr_d, mask_d, addr_s, mask_s, 0, true);
    else
	_default_key = 0;
    return 0;
}

int
T_RadixIP6Lookup::lookup_route(IP6Address addr_d, IP6Address addr_s, IP6Address &gw) const
{
    int key = _radix->lookup(_radix, _default_key, addr_d, addr_s);
    if (key) {
	gw = _v[key - 1].gw;
	return _v[key - 1].port;
    } else {
	//gw = 0;
	return -1;
    }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(T_IP6RouteTable)
EXPORT_ELEMENT(T_RadixIP6Lookup)

