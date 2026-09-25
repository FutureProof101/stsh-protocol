#!/usr/bin/env bash
# A6.5 sweep harness. NOTE: no `set -e` — a no-match member is a coverage
# outcome (F-11), never an abort (SSA D-6).
set -uo pipefail
P=504d85c8

# F-9: variable group count, 3-char tail. Fixing the count matches nothing.
PRIN='[a-z0-9]{5}(-[a-z0-9]{5})*-[a-z0-9]{3}'
CANI='[a-z0-9]{5}(-[a-z0-9]{5}){3}-cai'

# §0.3 declared field vocabulary — DATA, extensible upward only.
FIELDS='token_canister|staking_canister|founders_vesting_canister|fee_collector|treasury|controller|controllers|upgrader|vault|canister_id|canisterId|CANISTER_ID|pool_principal|m5_source_principal|frozenPoolPrincipal|beneficiary|principal'

# D-3: every producer normalised to a bare path BEFORE any set operation.
norm(){ sed "s/^$P://"; }

g1(){ git grep -lE "$CANI" $P -- . | norm | sort -u; }
g2(){ git grep -lE "($FIELDS)[\"']?[[:space:]]*[:=]" $P \
        -- deployment/ dfx.json canister_ids.json wallet/src circuits/ceremony scripts/cycle_monitor \
      | norm | sort -u; }
g3(){ { git ls-tree -r --name-only $P deployment/
        printf "dfx.json
canister_ids.json
wallet/src/session/config.ts
"
        printf "wallet/src/zk/spendManifest.json
circuits/ceremony/domain_manifest.json
"
        printf "scripts/cycle_monitor/config.local.example.json
"; } | sort -u; }
g4(){ cat <(g1) <(g2) <(g3) | sort -u; }          # THE universe U

# ── Emitter 1: value rows ────────────────────────────────────────────────────
# arm A — every literal canister-ID occurrence.  TSV: file line A - value
rows_a(){ git show "$P:$1" 2>/dev/null | grep -nEo "$CANI" 2>/dev/null \
          | awk -F: -v f="$1" '{print f"	"$1"	A	-	"$2}'; true; }
# arm B — every declared-field principal occurrence.  TSV: file line B field value
rows_b(){ git show "$P:$1" 2>/dev/null \
  | grep -nEo "($FIELDS)[\"']?[[:space:]]*[:=][[:space:]]*(opt[[:space:]]+)?(principal[[:space:]]+)?\"?$PRIN" 2>/dev/null \
  | awk -F: -v f="$1" -v FIELDS="$FIELDS" '{ ln=$1; $1=""; s=substr($0,2);
      match(s,/^[A-Za-z_][A-Za-z0-9_]*/);              fld=substr(s,RSTART,RLENGTH);
      if(index("|" FIELDS "|", "|" fld "|")==0) next;  # D-7: field must be a declared token
      match(s,/[a-z0-9]{5}(-[a-z0-9]{5})*-[a-z0-9]{3}$/); val=substr(s,RSTART,RLENGTH);
      print f"	"ln"	B	"fld"	"val }'; true; }
# dedup by (file,line,value); an overlap becomes arm AB and keeps its field name.
rows(){ for f in $(g4); do rows_a "$f"; rows_b "$f"; done \
  | awk -F'	' '{k=$1"	"$2"	"$5;
        if(k in arm){ if(arm[k]!=$3) arm[k]="AB"; if($4!="-") fld[k]=$4 }
        else { arm[k]=$3; fld[k]=$4 } }
      END{ for(k in arm){ split(k,a,"	");
        print a[1]"	"a[2]"	"arm[k]"	"(fld[k]==""?"-":fld[k])"	"a[3] } }' \
  | sort -t$'	' -k1,1 -k2,2n; }

# ── Emitter 2: file-level coverage, one line per U member (F-11) ─────────────
coverage(){ rows > /tmp/.a65rows
  for f in $(g4); do
    n=$(awk -F'	' -v f="$f" '$1==f{c++}END{print c+0}' /tmp/.a65rows)
    if [ "$n" -gt 0 ]; then st=VALUE-ROWS; else st=NO-VALUE-ROW; fi
    printf "%s	%s	%s
" "$f" "$n" "$st"
  done; }

g5(){ git grep -n "schema_version" $P -- deployment/ scripts/verify_genesis_manifest/ | norm; }
g6(){ git grep -l "schema_version" $P -- scripts/verify_genesis_manifest/tests/ | norm; }  # expect empty

case "${1:-report}" in
  report)   echo "A=$(g1|wc -l) B=$(g2|wc -l) C=$(g3|wc -l) U=$(g4|wc -l) rows=$(rows|wc -l)"
            echo "NO-VALUE-ROW=$(coverage | awk -F'	' '$3=="NO-VALUE-ROW"' | wc -l)" ;;
  universe) g4 ;;
  rows)     shift
            if [ $# -gt 0 ]; then                 # D-8: filter the CANONICAL stream
              rows > /tmp/.a65rows_all
              for f in "$@"; do echo "-- $f"; awk -F'	' -v f="$f" '$1==f' /tmp/.a65rows_all; done
            else rows; fi ;;
  coverage) coverage ;;
  g5)       g5 ;;   g6) g6 ;;
esac
