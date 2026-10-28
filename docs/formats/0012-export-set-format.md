# Export set, format 1

A customer must be able to take everything out of the archive and check it without us: when they leave, when we close, or when an auditor asks for the whole archive rather than one record. A real archive holds millions of records and terabytes, so no single file or request can carry it. Sets are kept for years and read by verifiers we don't control, so the format is fixed here, as the package's is (ADR 0009).

**The set** is a folder, pulled through the API by `archive-verify export`:

| Path | What |
|---|---|
| `export-set.json` | Format 1; the tenant; the legal entity, if the set holds one; when the export started and ended; counts per state; the audit head read before the catalogue and the one the set ends at; every other file with its SHA-256 and size; the packages that couldn't be fetched, with the reason. Written last: a folder without it is unfinished |
| `catalogue.jsonl` | One line per record, erased and purged ones included, ordered by record id: id, legal entity, type, state, retention class and its source, profile version, record date and its source, committed at, sealed at, expiry, retain-until, held, erased at and its basis, purged at. No names, subjects or file names: for an erased record this line is all that is left |
| `records/<id>.zip` | Each kept (committed or sealed) record's export package, format 1 (ADR 0009), unchanged |
| `audit/entries.jsonl` | The tenant's audit log from the first entry to the head, oldest first: each entry's fields, its content hash and its chain hash, lower-case hex |
| `audit/anchors/<id>.json` | For each daily anchor at or before the head: the tenant's head (sequence and chain hash), the leaf index, tree size and inclusion path to the anchor's root, and the root |
| `audit/anchors/<id>.tsr` | That anchor's RFC 3161 token, DER, as the provider sent it |
| `profiles/` | The profile versions the archive holds, as `GET /v1/profiles/.../versions/{n}` answers them. For reading |
| `README.txt` | What the set is, how to verify it, and that it holds every record's data key |

Nothing else may be in it. An anchor file carries only this tenant's leaf and proof, never the other tenants' heads, as a package carries only its record's seal proof (ADR 0007, ADR 0008).

**The hashes the log is checked by** are computed by `Archive.Evidence`, by the same code the server uses: the content hash in format 1 (ADR 0008), the chain hash SHA-256(previous ‖ content) from 32 zero bytes, and the anchor's 57-byte leaf. Test vectors computed outside .NET hold all three.

**The order of the export.**
1. The log's head (the *catalogue head*). Every record committed up to it is in the catalogue read next, since records are never removed from the catalogue, erased and purged ones included.
2. The catalogue.
3. Each kept record's package. A package that answers 410 was erased since the catalogue was read; it is left out, not counted as a failure.
4. The log's head again (the *audit head*), then the entries up to it and the anchors at or before it. Every commit and erasure the catalogue shows, and every erasure behind a 410, is therefore in the log. The entries the export itself adds after that head are the next set's.

The tool keeps its progress in `.export-state.json` and resumes from it, skipping packages and anchors already there: each file is written through a temporary one and moved into place, so a file there is whole. It deletes the state file after writing `export-set.json`. It refuses to resume a folder started for another tenant or legal entity, and to send its secret or receive data keys over plain http except on the machine itself. A package the archive refuses as damaged (502 with the archive's ProblemDetails) is named in the manifest; any other 5xx, a timeout or a dropped connection is tried again.

**The checks**, each named in the result, all run even after one fails:
1. `manifest`: `export-set.json` is format 1.
2. `files`: every file it names is there with its size and hash, and no other file is. A link or a device anywhere in the folder fails it, and the set isn't read further.
3. `fetched`: no package failed on the way out.
4. `catalogue`: every line reads and names a record once.
5. `packages`: every package passes the seven package checks (ADR 0009), is named by its record id, and is a kept record in the catalogue.
6. `anchors`: each anchor's leaf is this tenant's head at a sequence no later than the set's head, its proof leads to the root, and its token covers the root and chains to `--trust`.
7. `audit`: each content hash rebuilds from its fields and each chain hash from the one before, from the first entry; every anchored head is reached with the hash its anchor holds; the log ends at the head the manifest names.
8. `reconcile`: every record in the catalogue was committed in the log; every erased or purged one, and every kept one without a package, was erased there. In a set of the whole tenant, every record the log committed up to the catalogue head is in the catalogue, so a record can't be taken out of the set unseen.
9. `counts`: the manifest's counts are the set's.

All pass: the set is **valid** (exit 0), or **not yet proven** (exit 2) when some packages have no seal yet or no anchor holds the log. Otherwise it is **invalid** (exit 1). The result names the newest anchored entry and its time.

**What valid proves, and what it doesn't.** Each package proves its originals existed exactly like this at its sealing time. The log up to its newest anchor existed like this at that anchor's time, so a later rewrite shows; entries after it rest on the chain alone, a window of up to a day. A log no anchor holds proves nothing on its own: anyone can recompute every hash, which is why such a set is not yet proven. Neither proves the content true, nor that nothing was left out before the first anchor: the catalogue and the log are held only to each other. A set of one legal entity is held to the log one way only, since the log doesn't say which entity a commit was for; and the window after the newest anchor is open to a rewrite, as on the server.

An anchor file's tree size and path show how many tenants that day's anchor held, never who they are or their heads, as a seal proof shows its batch's size (ADR 0007).

## Considered Options

- **A server-side export job writing to a bucket the customer names.** It could start from the web front end, but it needs job state, a target store and its credentials, and the archive's storage would hold a second copy. Tenant exit (Q40) may want it later; the format stays the same.
- **One zip, or one request.** Neither survives terabytes or a dropped connection. A folder resumes file by file.
- **Packages without data keys**, verifiable but unreadable. That defeats taking everything out. The set therefore decrypts the whole archive (question 6 of the plan): the tool warns before it starts and the README repeats it, and protecting the set is the operator's duty.
- **The audit log checked only on the server.** Then "even if we're gone" would hold for the records but not for who did what to them.

## Consequences

Every verifier reads format 1 for as long as sets written in it are kept. A change is a new format number, never an edit of format 1. The audit content hash, the chain hash and the anchor leaf are now a contract with every set as well as with every stored chain: their code lives in `Archive.Evidence`, and the domain calls it.
