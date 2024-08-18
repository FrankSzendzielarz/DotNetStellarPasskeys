#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Vec};

const LOGS: Symbol = symbol_short!("logs");

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct LogEntry {
    pub timestamp: u64,
    pub source: Address,
}

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn extend_ttl(env: Env) {
        let max_ttl = env.storage().max_ttl();
        let contract_address = env.current_contract_address();

        env.storage().instance().extend_ttl(max_ttl, max_ttl);
        env.deployer()
            .extend_ttl(contract_address.clone(), max_ttl, max_ttl);
        env.deployer()
            .extend_ttl_for_code(contract_address.clone(), max_ttl, max_ttl);
        env.deployer()
            .extend_ttl_for_contract_instance(contract_address.clone(), max_ttl, max_ttl);

      
    }

    pub fn log_sign_in(env: Env, source: Address) {
        source.require_auth();

        let timestamp = env.ledger().timestamp();
        let log_entry = LogEntry {
            timestamp,
            source: source.clone(),
        };

        env.storage().persistent().set(&(LOGS, &source), &log_entry);
        Self::extend_ttl(env);
    }

    pub fn get_log(env: Env, source: Address) -> Option<LogEntry> {
        env.storage().persistent().get(&(LOGS, &source))
    }
}

