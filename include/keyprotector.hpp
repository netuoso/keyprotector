#include <eosio/transaction.hpp>
#include <eosio/eosio.hpp>
#include <keyconvert.hpp>

using namespace eosio;
using namespace std;

CONTRACT keyprotector : public contract {
   public:
    using contract::contract;

    TABLE info {
    	name o;
    	string ok;
    	string ak;

    	uint64_t primary_key() const {return o.value;}
    };

    typedef eosio::multi_index<"info"_n, info> infotable;

    ACTION setkeys( name o, string ok, string ak );
    ACTION run( uint64_t i );
    ACTION stop();

    using setkeys_action = action_wrapper<"setkeys"_n, &keyprotector::setkeys>;
    using run_action = action_wrapper<"run"_n, &keyprotector::run>;
    using stop_action = action_wrapper<"stop"_n, &keyprotector::stop>;

  private:
  	bool decode_base58(const string& str, vector<unsigned char>& vch) {
	    return DecodeBase58(str.c_str(), vch);
		}

    struct signup_public_key {
        uint8_t        type;
        array<unsigned char,33> data;
    };
    struct permission_level_weight {
        permission_level permission;
        uint16_t weight;
    };
    struct key_weight {
        signup_public_key key;
        uint16_t weight;
    };
    struct wait_weight {
        uint32_t wait_sec;
        uint16_t weight;
    };
    struct authority {
        uint32_t threshold;
        vector<key_weight> keys;
        vector<permission_level_weight> accounts;
        vector<wait_weight> waits;
    };

    vector<unsigned char> keyToVector(string k) {
			vector<unsigned char> kv;
			auto kstr = k.substr(3);
			check(decode_base58(kstr, kv), "Decode owner pubkey failed");
			check(kv.size() == 37, "Invalid owner public key");

			return kv;
    }

  	void setpermission(name o) {
			infotable info(_self, _self.value);
			auto itr = info.find(o.value);

			check(itr != info.end(), "user must call setkeys first.");

			print("setting permission for ", o);

			auto ov = keyToVector(itr->ok);
			auto av = keyToVector(itr->ak);

  		auto permlev = permission_level{_self , "eosio.code"_n };

      permission_level_weight acctperm_weight = {
          .permission = permlev,
          .weight = 1,
      };

      array<unsigned char,33> ownerpub_data;
      copy_n(ov.begin(), 33, ownerpub_data.begin());

      array<unsigned char,33> activepub_data;
      copy_n(av.begin(), 33, activepub_data.begin());

			signup_public_key ownerpub = {
        .type = 0,
        .data = ownerpub_data,
      };
      key_weight ownerpub_weight = {
        .key = ownerpub,
        .weight = 1,
      };
			signup_public_key activepub = {
        .type = 0,
        .data = activepub_data,
      };
      key_weight activepub_weight = {
        .key = activepub,
        .weight = 1,
      };
      authority ownerauth = authority{
	      .threshold = 1,
	      .keys = {ownerpub_weight},
	      .accounts = {acctperm_weight},
	      .waits = {}
      };
      authority activeauth = authority{
        .threshold = 1,
        .keys = {activepub_weight},
        .accounts = {acctperm_weight},
        .waits = {}
      };

			action(
	      permission_level{ o, "owner"_n },
	      "eosio"_n,
	      "updateauth"_n,
	      make_tuple(o, "active"_n, "owner"_n, activeauth)
			).send();
			
			action(
				permission_level{ o, "owner"_n },
				"eosio"_n,
				"updateauth"_n,
				make_tuple(o, "owner"_n, ""_n, ownerauth)
		  ).send();
  	}
};
