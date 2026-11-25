# Rules for the requirements list

rust-idp's [requirements list](./) (the seven lists) was built with the rules on this page. The requirements list itself is in Japanese. This page is an English translation of the rules.

This page defines the seven requirement lists and the rules for writing them. The seven lists are: the object × operation × permission table, the screen list, the settings list, the external systems list, the external object × operation list, the data model list and the procedure list. The center is the object × operation × permission table. Five lists (screens through data model) link to the table by pointing at the IDs of its operations. Only the procedure list has an order. For each goal, it names who does what, in which order, by pointing at row IDs in the other six lists. The external object × operation list splits one row of the external systems list into objects and operations. It has the same shape as the object × operation × permission table.

The page holds only rules that apply to any system. The examples use EC-CUBE (4.3.1), a public open-source shop system.

Terms used on this page:

- **Script**: the program that builds and checks the lists.
- **Promise**: a behaviour that a test commits to keep. Only systems with a mechanism for managing promises use them.
- **Red**: a test or check fails.
- **Confirmed / inferred**: a link traced through the code is confirmed. A link guessed from names or types is inferred.

The Japanese terms in parentheses are the column and value names used in the Japanese list.

## Rules for every list

1. The counts in a list (rows, items) come from the script that builds it. Do not write them by hand in documents or pages.
2. In a system that manages promises with a separate mechanism, do not put promise text or promise IDs in a list. They live only in that mechanism. Each list row gets one promise mark column, which the script fills from that mechanism.
   - The mark is one of four values: yes (direct), yes (through the parent), no, not needed. "Yes (direct)" means a promise names this row. "Yes (through the parent)" means the linked table operation has a promise. "Not needed" means there is nothing to make a promise about. In the object × operation × permission table, a link that only matches words of the promise text does not count.
   - A system without a mechanism for managing promises has no promise mark column.
3. Separate links by certainty. A chain traced through the code is "confirmed" (確か). A link guessed from names or types is "inferred" (見込み). On the page, an inferred link is shown as a dotted tag.
4. Do not write expected questions and answers as a separate source of answers. One row of a list is the source of the answer. An LLM rewords it to fit how the question was asked. A test measures whether the answers stay on target.
   - "Trial questions" that point at list row IDs (questions to show people, questions for tests) may live in a file separate from the lists. Each answer is written as a row ID and the supporting file:line. Do not copy the row's content. The script checks that every row ID a question points at exists.
5. Numbers used only for cross-checking (such as the number of links) stay inside the script. Do not show them on the page.
6. The promise mark comes from two sources: promises whose tests call an entry point of the operation, and currently valid promises tied to a requirement that names a list row ID. Rows of the external object × operation list are read the same way. A promise that is no longer valid is removed from the mark.
7. The tools for the rules that check a list is complete (table 20, settings 14, external 14, data 15) include four mutations as negative controls: a missing row (delete one), a duplicate (list it in two places), out of scope (a row outside the owner points at it), and an ambiguous citation (two files with the same name, so the reference cannot be resolved). Count that the mutations were applied before running. When the result is red, exit with code 1.
8. Write "six lists" only for the six lists other than procedures. Write "seven lists" for the whole set.
9. A list records the version it was built from (repository and commit SHA). When the source changes and the requirements change with it, rebuild the list and every copy made from it.
10. In a system with isolation units inside one deployment (organizations, tenants and so on), split "everything" by breadth. Everything inside one unit is "everything in the <unit>". Anything across units is "everything in the deployment".
11. Judge the table marks under the production configuration. When a row or cell changes value with the configuration (such as the number of isolation units), do not split the cell. Write the configuration in the condition text. The configuration itself goes in the deployment-shape row of the settings list (settings rule 20).

## Object × operation × permission table

1. Write the requirements in one table. A row (parent) is one operation of the core system. Under it (children) are the entry points that call that operation.
2. A parent row has "object and reached-through" and "operation". Reached-through is one of: parent, requester, scope, everything, direct. In a system with isolation units, split "everything" into "everything in the <unit>" and "everything in the deployment" (common rule 10).
3. Decide the operation by what changes on the object. Write it as one of six patterns (list, create, get, replace, update, delete) or as a kept verb.
4. If only a field changes and the reverse operation undoes it, it is an update. If nothing changes, it is a get.
5. A thing that links two objects (an intermediate object) gets its own row. Linking and unlinking are create and delete on that row.
6. Keep a verb only when it does one of these: creates another object, sends something out, cannot be undone, is allowed for different people than update, or is a multi-step procedure. Use nine generic words plus words the product adds, with the original wording underneath.
7. For an object that exists only once (has no ID), list and create are "not applicable".
8. Split entry points by the kind of door through which the core is called (for example: API route, AI tool, component screen, operations tool (CLI), internal trigger). Write the "calls" target on the child row. A screen goes under the operation it calls. An operations tool means a command typed by the deployment's operator.
9. An operation with no entry point gets one of two tags: "not implemented (missing feature)" or "runs on an internal trigger (time, startup, inside an AI turn, a gate on every route)".
10. A permission column is a pair of "who" and "relation to the object". Decide who and relation from the system's real roles, and explain each in a legend (for example, EC-CUBE's who are system administrator, shop owner, member and non-member).
    - A who with no relation to the object (a mechanism on an internal trigger, the deployment's operator and so on) gets one column that is not split by relation.
    - An administrator acting as someone else (impersonation) counts as "the person acted as", not in the administrator column. The administrator column is the decision when administrators call as themselves. Write the routes reached through impersonation in the row's condition text. Also write in the condition text any case where an identity on one surface changes the decision on another (impersonation, viewing the storefront while signed in as an administrator, and so on).
11. For a who that acts on someone's request (an AI and so on), write whether it borrows the requester's relation.
12. Decide relations from intermediate objects and object fields. Do not create a relation column that the table cannot name.
13. A cell value is one of: allowed (可), denied (断), conditional (条件つき), not applicable (該当しない), no route (口無し), unchecked (未確認). Never leave a cell empty.
    - "Not applicable" means the operation has no meaning for that who. "No route" means it has meaning but that who has no route to call it (for example, a shopper who is not signed in viewing their own order). Rule 9's "not implemented" is for when no who has a route. "No route" is for when only some who columns lack one.
14. Write a conditional cell as a setting name or an object field value.
15. When denying, state whether the object is invisible (not in the list) or visible but denied.
16. Write permissions on the parent row. Only when they differ by entry point, write "differs by entry point" on the parent and give values on the children that differ.
17. For objects that can gain relations later (sharing, invitations, adding members), write on the row of the adding operation who may add.
18. Write a gate that applies to every row (suspension, allow lists and so on) once, outside the table, and mark the rows it applies to. Name the rows it does not apply to.
19. Find gaps by applying, per object, the six OAS (OpenAPI) patterns and the nine many-to-many patterns. Sort each result into: already listed, a new gap, missing from the table, or does not apply.
20. Check that the table is complete in two ways. First, every entry point of the core (API routes, AI tools and so on) appears exactly once as a child, and every operation appears exactly once as a parent. Second, each allowed and each denied cell is linked to the core's authorization code (file:line) or to a test. List health checks, inbound receivers and pass-through routes outside the table.
21. In a system that manages promises, put the promise mark on the parent row (common rule 2).
22. Put "from screens" on the parent row, with the IDs of the screens and menus that call the operation. Leave it empty for an operation no screen calls. The script builds this field from the screen list's "calls" and "destination". Do not write it by hand.
23. Put "settings that apply" on the child row. List the settings whose effect target is ① entry point and that change whether this route is allowed or denied. A cell's value is the value with the setting at its default. Each tag carries the setting name, when it applies, before → after, confirmed / inferred, and the evidence. Do not show it on the parent row.
    - Judge table marks under the production configuration. Other settings take their default values.
24. In the child row's entry point field, add the external systems the route calls, by their IDs in the external systems list.
25. In a product whose permission keys (URL prefixes, route names, roles and so on) differ in shape from business units, put a "blocking key" column on the parent row. Write which key makes that row denied. Write once, outside the table, how keys are matched (prefix, regular expression, exact match). Name the rows where the business name and the key do not line up (for example, an order operation under the shipping prefix).
26. When updating a state field moves another object (side effects such as stock or points), add a separate row whose who column is "mechanism", apart from the update row. For each transition, write what moves and which transition moves it back. Link it from the row of the operation that triggers it. When transitions or side effects are written in a configuration file, use that file:line as evidence. Rule 4's "undone by the reverse operation" does not apply when undoing moves another object.
27. Extension points (event names, replaceable hooks and other places where outside code adds behaviour to the core) are not entry points. List them outside the table. For each, write the file:line where it fires, and name the ones the core never fires. State at the top of the table that behaviour added through extension points is outside the table.

## Screen list

How it differs from the table: the table has two axes (object × operation), so an empty cell is directly a gap candidate. The screen list is a tree on one axis (screens). Gaps are found as "operations no screen calls" and "screens nothing leads to".

1. A row is one screen or one menu item.
2. Group rows by surface (for example: user screens, admin screens, entry and sign-in screens, chat, mail, AI text).
3. Write screens as a tree. A menu item records the screen it sits on (parent) and its destination (rule 13).
4. A screen row lists the core operations the screen calls, by table ID.
5. Build rule 4 from the table's "component screen" entry points. Do not count the same thing twice across the table and the screen list.
6. Write the condition for showing a screen (role, feature flag) as a flag name or an object field value.
7. Do not copy who may operate onto the screen. Refer to the table's permissions.
8. Compare with the table, and name places where a screen shows but the operation is denied, and places where the operation is allowed but no screen exists.
9. Write screen-only operations that do not call the core paired with the table's "calls: unchecked".
10. Every operation on a surface people use appears in some screen row. For one that does not, write the reason: "AI only" or "API only".
11. Every screen can be reached from a menu. Tag a screen that cannot be reached with "opened directly by link".
12. Wording on screens (translation) is left to other rules and is not covered here.
13. A menu row has a "destination". The destination is one of these four:
    - Move: the ID of the screen it opens
    - Operation: the ID of the core operation it calls (a table parent)
    - In-screen only: sends no request to the core; only opens, copies or saves locally within the screen
    - Not in the table: pressing it makes the core act, but the table has no row for that operation. Write in one sentence what happens, with the supporting file:line
14. The tree has three levels. Level 1 is the surface entry (the outermost frame), level 2 is screens and menus, level 3 is menus only. Do not put screens on level 3.
15. A menu item is something that moves to another screen, runs a core operation, or changes what the screen shows when pressed. Include not only the left navigation but also right-click items, card buttons and filter tabs. Most buttons inside a screen are not menu rows. They go in the screen row's "calls".
16. Keep a menu whose destination is "not in the table" until it is decided whether to add a row to the table or to write why it stays outside.

## Settings list

How it differs from the table: the table has two axes (object × operation), so an empty cell is directly a gap candidate. The settings list is a sequence on one axis (settings). For each row, the location, scope and who changes it are nearly fixed (an environment setting belongs to the whole deployment and the operator; an admin-screen setting belongs to the organization's administrator). So gaps are found as "settings with no way to change them" and "overlaps whose precedence cannot be named".

1. A row is one setting (one environment variable, one field in a configuration file, one setting in the database).
2. A row has the fields: name, location, type, scope, who changes it, how to change it, default, where it is read, and effect. It also has: effect target (rule 15), where it applies (rules 16 and 17), external (rule 19) and parent. In a system that manages promises, it also has a promise field (common rule 2).
3. The location is environment, configuration file or database. For a database setting, add where it comes from (admin-screen setting, feature flag, personal setting, a table object and so on).
4. The scope is whole deployment, organization, sub-scope or individual. For a sub-scope, write how it combines with the organization's value (lower bound, upper bound, override, either is on).
5. Who changes it is operator, organization administrator, the person themselves, or unchangeable. For a database setting, take it from the table's permissions (the parent row of the changing operation).
6. Write how to change it as admin screen, user screen or API route, by the table's parent ID. For a setting with no way to change it, write how to fix it, such as "none (edit env and redeploy)".
7. For the default, write the value found on the reading line. When the line has none, write "none on the reading line".
8. For where it is read, write the file:line in the current tree. Do not use lines borrowed from another tree.
9. Write the effect in one sentence about what changes. Never write secret values.
10. When settings with the same meaning exist in two or more locations, group them as one overlap. Write the precedence (database wins, environment wins, both required, both apply side by side) and the supporting file:line.
11. When another tool generates an environment variable from a configuration file field, put them in an overlap and write the precedence as "generated from the configuration file".
12. Name things written to the same location through two or more routes, separately from overlaps.
13. List readers whose setting name is decided at run time, and readers in places that cannot be opened, under "could not be read".
14. Check that the list is complete in two ways. First, every place the system reads a setting (environment variables, configuration file fields, database settings) appears exactly once. Second, every parent ID written under "how to change it" exists in the table.
15. The "effect target" is exactly one of these four, with confirmed / inferred:
    - ① Entry point: changes whether a table route is allowed or denied
    - ② Result: the route stays allowed, but the result changes (size, wait time, content and so on)
    - ③ Connection: an external system's destination, key or credentials
    - ④ Foundation: what the core runs on (URL paths, upstreams, how it starts and so on)
    - Before writing ① entry point, check on the reading line whether it acts on the route side (the core's decision). A setting that only shows or hides a screen component while the route stays open is not ① entry point. Tag it "appearance only", and write the IDs of the routes that stay open under "where it applies".
16. For a ① entry point setting, write under "where it applies" the IDs of the table routes (child rows) it narrows, with when it applies, before → after and evidence. On the table side, show the same link as "settings that apply" (table rule 23). For a ① entry point setting that narrows no route, write why.
17. For a ② result setting, write in one sentence where it applies. Leave "where it applies" empty for ③ and ④. Link ③ through the external systems list's "setting that enables it".
18. In a system that manages promises, do not write one promise per settings row. Cover each field (default, effect, precedence, who changes it) with a promise that walks every row. Check that such a promise turns red under a mutation that changes one row's default or reverses a precedence.
19. In the "external" field, write the external systems the setting applies to, by their IDs in the external systems list.
20. Put the "deployment shape" (OS, language and framework versions, how it runs, number of instances) in a settings row. Whether a vulnerability applies can depend on this row rather than on a route, so the requirements should be able to answer it. Its location is "deployment" (a fourth location added to rule 3's environment, configuration file and database, used only for this row). Its effect target is ④ foundation. Deployment procedures (migrations, canaries, how releases proceed) are not this row. They go on a branch of the requirements tree (the first item under "What stays outside the lists").

## External systems list

How it differs from the table: the table has core operations as rows. The external systems list has outside parties as rows, and links to the table by pointing at parent IDs. A family × system table would repeat many names and leave most cells as "–", so each system is one row.

1. A row is one external system. Write the family (AI provider, a person's linked account, inbound receiver and so on) in the row's "purpose".
2. Separate systems by the counterpart service that holds its own set of keys and settings. Even within one company, a different set means a different row.
3. The kind is "external party" or "infrastructure". Infrastructure is anything that supports the core's records, deployment, measurement and so on.
4. The direction is "outbound", "inbound" or "both". For inbound, write how it is verified (signature).
5. Choose the authentication form from OAuth, key, signature or none. When it differs by purpose, list them side by side.
6. Write whose authority the call uses: organization (company key), person (the person's connection) or deployment (environment key). This field decides whose costs, quotas and records the call counts against.
7. Write the setting that enables it by setting name, the same name as in the settings section.
8. Write the core operations that call it by table parent ID. For something every operation goes through (database, error reporting and so on), write "every parent (cross-cutting)".
9. For pass-through routes, write the place where the core goes out as file:line. Name exits that exist only outside the core (development tools, distribution scripts and so on) separately as "outside the core".
10. Describe how a failure looks as "denied", "waits" or "fails silently". For one that fails silently, add the place that swallows the error (file:line).
11. When a gate narrows traffic from the core to the outside, write it once as a gate outside the table (table rule 18). Do not put it in a system row.
12. Put an exit whose destination is decided by a setting or argument on some row, together with the name of the setting that decides the destination. Name the ones that cannot be placed as "cannot be linked".
13. Do not list dependencies that do not talk to the outside (screen components, parsers and so on). Put them in a separate component list.
14. Check that the list is complete in three ways. First, every outbound door of the core appears exactly once, as a system row, a component, or outside the core. Second, every exit whose destination is a value is accounted for. Third, every parent ID linked exists in the table.

## External object × operation list

The external systems list has one row per system. So it cannot say what the core reads, creates or deletes at the external system, or under whose authority. This list splits the external systems list one level further. It is the source of answers when someone asks how an external system is used. It answers what the core does to the external system. It does not cover behaviour inside the external service.

1. A row is one external object (a mail message, a calendar event, a chat message, an issue and so on) × one operation (list, get, create, update, delete, send, receive and so on).
2. A row has the fields: external system (ID in the external systems list), external object, operation, calling tool, core gate, external gate, destination of results, confirmed / inferred.
3. Write the calling tool as the core-side entry point (AI tool name, API route, cron, webhook receiver) with file:line.
4. For the core gate, write the decision that allows or stops the call (permission, setting, role), linked to a table parent ID.
5. For the external gate, write whose token makes the call (organization key, the person's OAuth, a mechanism), the scopes requested, and the permissions needed on the external side.
6. For the destination of results, write the core object the result goes into and its sharing scope there (the person only, participants, the organization and so on). If nothing goes in, write "not stored".
7. A counterpart whose tools are decided at run time (an MCP server and so on) cannot have its objects listed. Give it one row and write only the core gate and the external gate.
8. The checked items are the core gate, whose token, and the destination with its sharing scope. In a system that manages promises, these three become promises. The scopes of the external gate and the permissions on the external side cannot be checked without calling the external system. Include them as explanation and mark them "inferred".
9. The scope of this list is external parties (rows of the external systems list whose kind is "external party"). Infrastructure comes later.
10. From each row of the external systems list, allow moving to the external object × operation list filtered to that party. From each external object × operation row, allow moving back to that external system row.

## Data model list

How it differs from the other lists: the other lists have what the core does as rows. The data model writes what the core records, one database table per row. A row's content is written in the data model notation (the way of writing set by rules 5–12). On the page it is split into table fields, and each row's original notation can be opened and read.

1. A row is one database table. The script writes rows out from the database catalogue of the production tree. Do not add rows by hand.
   - Row IDs are sequential numbers in the form D-001. The mapping from table names to numbers is fixed in one file. When a table is added, it takes the next number. The number of a removed table is never reused. Other lists point at tables by this ID. Notation lines keep the table name.
2. Decide the table kinds from the shape of the system's database (for example: tables with columns, tables holding only a key and a JSON value, and "outside objects" that have no table in the database but are pointed at by IDs).
3. Keep the table name as it is in the database (English, plural as is). When adding a Japanese name, use a simple word that does not distinguish singular and plural.
4. A table without a Japanese name is shown as "no name" with the mark `?{table name}`. The script outputs the number of unnamed tables.
5. Write relations between tables with three symbols. `--` means the row is deleted with its parent (database CASCADE). `->` means the target cannot be deleted while it is pointed at. `~>` means it points at the target but the database does not enforce it.
6. Separate relations by certainty. One with a database foreign key is "declared". One with no foreign key, where the code was checked to match the IDs, is "code" (`<logical code>`). One guessed only from names or types (`<logical guess>`) is not listed.
7. Name columns that hold an ID but are not made relations as "columns not made relations", with a one-line reason (a column mixing two kinds of value, a column with no place that writes it, and so on). Do not drop them silently.
8. For an ID whose target table is not fixed (a column that points at one of several outside objects depending on its value), list the targets as `{a|b via column}`.
9. Write a time stored as an integer (milliseconds) as `datetime(ms)`. The same applies to keys inside JSON.
10. Write a reference from a key inside JSON as `via column.key`. Write a reference to a set of non-primary-key columns as `via (..) to (..)`. The `to` set must be the same as one of the target's `@unique` sets, or contain the target's whole primary key.
11. Write physical properties (index names, descending order, index method, CHECK names, types missing from the notation, table settings and so on) apart from the logical lines, on `@pg` lines at the end. On the page, show only their count in the "physical" field.
12. Keep things the notation cannot express (JSON keys not read, type aliases, extends, vectors without a dimension and so on) on the table's row as "cannot be expressed". The script outputs the count for each kind.
13. Put a "tables recorded" column on the parent rows of the object × operation × permission table. List, as D ID tags, the tables the operation reads or writes when traced from its entry point. Put the reverse "operations using it" column on data model rows. A path traced from the entry point to the function that touches the table, through at most two levels of helpers, with file:line, is confirmed (solid line). One that only matches by name is inferred (dotted line). Do not make tags for tables reached only through a shared prefix (authorization wiring and so on), or only on a failure path. Show only their count.
14. Tables that many operations go through (audit, error records, authorization rosters, version checks and so on) are "cross-cutting" and are not shown as tags in the main table. Name every table linked to no operation, with one of these reasons: "internal mechanism", "beyond an asynchronous boundary" or "could not be traced". Do not mix "could not be traced" with "internal mechanism".
15. Check that the list is complete in three ways. First, every table in the catalogue becomes exactly one row. Second, every relation target exists as a row. Third, every `@pg` line can be linked to some table.
16. Besides database tables, add rows for business objects kept outside the database (template files edited from screens, a .env written by a screen, uploaded files and so on) as "holdings outside the database". Write the location and the IDs of the operations that write them. This lets a row answer what a migration or backup must cover. Rule 1's "do not add rows by hand" applies only to database table rows.

## Procedure list

How it differs from the other lists: the other six hold parts (who can do which operation, which screens and settings exist). They do not hold the order of steps, or the preparation outside the core (at outside providers). A procedure is the source of answers to "to make X possible, whom do I ask for what, and what do I do in which order?". Each step names rows in the six lists.

1. A row is one goal, with a sequential ID in the form T-00. Steps go under the goal, with IDs in the form T-01-1. When one step splits by provider, use branches T-01-1a to 1d.
2. When a goal depends on another goal, name that goal's ID in the "prerequisite" field. T-00 is the deployment foundation every procedure depends on (settings the operator touches that apply to many operations).
3. A step has the fields: step kind, who, relation, provider, what to do, check, and rows in the six lists.
4. The step kind is one of five: "external preparation", "deployment setting", "organization setting", "personal preparation", "object × operation".
5. Choose "who" from the who of the permission columns in the object × operation × permission table. A who with no relation to objects, such as the deployment's operator, also has the one unsplit column of table rule 10.
6. Write the relation only when you want to name the relation to the object. When it is not written, it is enough that one of that who's relations allows it.
7. The check is one of: "passed in production", "from on-screen guidance", "none", "depends on the AI's choice". For a step passed in production, write the date checked and the provider on the goal row. "Depends on the AI's choice" is for steps that change with which tool the AI picks in that turn.
8. In the six-lists field, write the IDs of the operations (A-), screens, settings, external systems (X-), external object × operation rows and data model rows (D-) the step touches. Copy the names of items on a provider's screens exactly as the provider's screen shows them.
9. When the script builds the page, it checks the procedures against the six lists. If any of these holds, it stops without building the page:
   - a named ID is not in the six lists
   - a named operation is neither allowed nor conditional for the step's "who" (or the relation column, when one is written)
   - a step for a who not split by relation (the deployment's operator, a mechanism and so on) names a setting that who does not change
   - a goal named as a prerequisite does not exist, a step ID appears twice, or kind, who, relation or check is not one of the fixed words
10. Procedures are not made into promises. The check in rule 9 stops the build and reports when a procedure has gone stale.
11. In a system that manages promises, put first in line for becoming promises the operations named by procedures whose promise mark is "no" or "unchecked".
12. When answering, answer only with procedures for goals that are written. For a goal that is not written, answer "this list has no procedure for it". Do not infer an order from the parts in the six lists. Even within a written goal, do not fill steps marked as not written from the six lists.
13. Draw goal candidates from objects that have write operations in the object × operation × permission table, and add them one at a time.
14. Keep procedure data in one file. The script builds the procedures tab of the page from it. Make any copy from that file.

## Building lists for a system with master data

This method was checked against the EC-CUBE 4.3.1 code.

- Master data means tables an administrator registers before opening for business, which change the routes users take (products, delivery methods, payment methods, lodgings, room types, plans and so on). Shops and booking systems have them.
- In the data model list, mark the master tables.
- For each master table, list its "type fields". A type field is a field that code branches read (validation, what a screen shows, routing). For example, for EC-CUBE products the type fields are the number of variants, "do not count stock", the purchase limit, and the sale type. Do not list the values themselves (individual products).
- Write the chain between types. In EC-CUBE, the sale type narrows the delivery methods, and the delivery method narrows the payment methods. If the chain reaches zero along the way, the item cannot be bought.
- Use two axes for the grid: "shop switches × master types". The rows are only the type combinations that change the route. Include combinations that reach zero along the chain.
- Make example questions for each master type too.
- Start the permission levels from administrator and general user. Administrators may split into the operator and per-site administrators (per lodging, in a booking system). General users may split into members and guests. Write "my site" and "my booking" in the relation column of the object × operation × permission table.
- When external systems make up a large part of the requirements (OTAs for a booking system and so on), interview before building the lists. Ask: the number and names of counterparts, direct or through a site controller, which side is the source of truth for each object, how notices arrive, how double bookings are handled, and whether specifications, test environments and contracts exist. The answers change the row counts of the two external lists, and the estimate, a great deal.

## What stays outside the lists

- Operations and deployment procedures (migrations, canaries, how releases proceed and so on) are not a new list. Add them as one branch of the requirements tree (a document that lays out requirements as branches), and link shell checks to that branch. The running deployment shape (OS, versions, how it runs, number of instances) is a settings row under settings rule 20. The branch holds deployment procedures; the row holds the deployment shape.
- Rules that cut across all lists are not a new list. Keep them separately as cross-cutting rules.
