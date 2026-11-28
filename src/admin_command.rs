//! 管理者用サブコマンドの名前。gcp 付きの binary は実行し、gcp 無しの binary は名前を見て断る。
//! 名前はここにだけ置き、gcp.rs は列挙子で分岐する（足し忘れは match の網羅で止まる）。

#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminCommand {
    Mint,
    RevokeClient,
    GrantAdmin,
    RevokeAdmin,
    DisableAccount,
    EnableAccount,
    MigrateStaticClients,
    MigrateCredentials,
    SetClientScope,
}

impl AdminCommand {
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "mint" => Self::Mint,
            "revoke-client" => Self::RevokeClient,
            "grant-admin" => Self::GrantAdmin,
            "revoke-admin" => Self::RevokeAdmin,
            "disable-account" => Self::DisableAccount,
            "enable-account" => Self::EnableAccount,
            "migrate-static-clients" => Self::MigrateStaticClients,
            "migrate-credentials" => Self::MigrateCredentials,
            "set-client-scope" => Self::SetClientScope,
            _ => return None,
        })
    }
}
