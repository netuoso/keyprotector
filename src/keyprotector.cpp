#include <keyprotector.hpp>

ACTION keyprotector::setkeys( name o, string ok, string ak ) {
	require_auth(o);

	infotable info(_self, _self.value);
	auto itr = info.find(o.value);

	auto ov = keyToVector(ok);
	auto av = keyToVector(ak);

	if (itr != info.end()) {
		info.modify(itr, _self, [&](auto& ob) {
			ob.o = o;
			ob.ok = ok;
			ob.ak = ak;
		});
	} else {
		info.emplace(_self, [&](auto& ob){
			ob.o = o;
			ob.ok = ok;
			ob.ak = ak;
		});
	}
}

ACTION keyprotector::run(uint64_t i) {
	require_auth(_self);

	infotable info(_self, _self.value);
	auto itr = info.begin();
	
	while(itr != info.end()) {
		setpermission(itr->o);
		++itr;
	}

  transaction deferred;

  deferred.actions.emplace_back(
    permission_level(_self, "active"_n),
    _self, "run"_n, make_tuple(i)
  );

  deferred.delay_sec = i;
  deferred.send(_self.value, _self, true);
}

ACTION keyprotector::stop() {
	require_auth(_self);

	cancel_deferred(_self.value);
}
