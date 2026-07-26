# 設計ノート

CLAUDE.md の「拡張安全性の判断基準」に基づき、新しい公開型/trait/関数シグネチャを導入した箇所の判断を記録する。

## CodeStore は trait 化しなかった (src/store.rs)

将来 Firestore 永続化に置き換える予定はあるが、CLAUDE.md の「FAPI 2.0 / CIBA / WebAuthn / Firestore永続化は、素朴な土台が動いてから段階的に足す」という方針に従い、今 felt need がない抽象化(`trait CodeRepository` 等)は先回りしなかった。`CodeStore` は具体的な struct のまま。Firestore対応が実際の作業になった時点で、その時のインターフェース必要性を見てtrait化するか判断する。
