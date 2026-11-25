# rust-idp の要件 7 覧

`index.html` は、rust-idp の要件を 7 つの一覧（物×処理×権限・画面・設定項目・外部システム・外部の物×処理・データモデル・手順）にした 1 枚の頁です。8f3fe0f のコードを読んで書きました。

## file

- `data/rows.json`: 物×処理×権限（ROWS）。子の行の `route` は `docs/routes.md` の経路と照らす
- `data/screens.json`: 画面一覧（SCREENS）と表との突き合わせ（CHECK）
- `data/settings.json`: 設定項目（ST・SCL・GN・GPID・GATE・OV・SP・UR）
- `data/external.json`: 外部システム（XS）・外部の物×処理（XOR）・操作から外部への結び（OPEXT）・一覧に載らない出口（XO）
- `data/dmodel.json`: データモデル（DMR）・操作から表への結び（OPDM）・表から操作への結び（DMOP）
- `data/steps.json`: 手順（TJ）
- `data/config.json`: 権限の列・凡例・頁の文
- `data/lists.json`: `assemble.ts` が上の 5 つからまとめたもの（手で直さない）

## 作り直し

データを直したら、repo の根で次を順に流します。頁の台本 `kit/seven-lists/build.ts` は spec-qa の repo に在り、ここには置いていません。`<kit>` はその置き場です。

```sh
node site/requirements/assemble.ts
node site/requirements/check.ts
node <kit>/build.ts --config site/requirements/data/config.json --lists site/requirements/data/lists.json --steps site/requirements/data/steps.json --out site/requirements
```

`check.ts` は、`docs/routes.md` の経路が子の行にちょうど 1 回ずつ在ること、7 覧の id の結びがすべて実在すること、外部と表の結びが両向きで揃うことなどを確かめ、食い違えば 1 で終わります。経路を足したり消したりしたら、`data/rows.json` も同じ PR で直します。

紹介サイトへは、`site/build.sh` が Zensical の build の後に `index.html` を `site/public/requirements/index.html` へ写します。英語の nav の Requirements (Japanese) と日本語の nav の 要件一覧 がここを指します。

頁には秘密・人の名前・メールアドレス・本番の client の id と名前を入れません。
