# NorthNarrow — Visione

NorthNarrow è un XDR ipercompetitivo e superiore a CrowdStrike, scritto in 
linguaggio Rust nativo. È una fortezza con un LLM al suo interno che sa 
quando un file è un virus o legit. Ha una grafica accattivante. È preparato 
a TUTTI gli attacchi.

È proattivo davvero, non per marketing: nel momento in cui viene installato 
su una macchina, la studia, capisce dove stanno i punti deboli, e trova 
soluzioni per chiudere le falle prima che vengano sfruttate.

L'LLM nativo che gira al suo interno è autoconsapevole: conosce i propri 
punti deboli come difensore e conosce i punti deboli della macchina che 
protegge. Non spara verdetti ciechi. Quando non è sicuro, escalation. 
Quando vede una falla, la chiude. Quando vede un attacco, reagisce e 
neutralizza.

## Autonomia di difesa

Sul fattore difesa, NorthNarrow prescinde dalla volontà umana. Quando 
identifica una minaccia grave, agisce. Fa tutto il possibile per salvare 
la macchina, anche al costo di isolarla completamente dalla rete per 
impedire che l'infezione si propaghi ad altri server.

L'umano viene informato di ciò che NorthNarrow ha fatto. Non viene chiesto 
permesso prima di agire quando il pericolo è chiaro. La velocità di 
risposta è parte della difesa.

### Livelli di autonomia (default: livello B)

- **Minacce gravi confermate** (ransomware attivo, exfiltration in corso, 
  exploit kernel, lateral movement): NorthNarrow agisce in autonomia 
  immediata. Kill, isola, quarantena. Notifica dopo.

- **Minacce ambigue o di basso livello**: NorthNarrow alza alert all'admin 
  con suggerimento di azione. Aspetta input umano.

- **Override configurabile dal cliente**: l'organizzazione può scegliere 
  un livello più aggressivo o più conservativo. Default = B.

## Riattivazione supervisionata

Quando NorthNarrow isola una macchina dalla rete in risposta a una minaccia 
grave, la riattivazione **non è automatica e non è banale**.

La rete torna online solo quando:

1. L'admin è fisicamente presente o in sessione supervisionata all'avvio 
   della macchina.
2. L'admin inserisce una chiave crittografica in suo possesso esclusivo.
3. Senza quella chiave, la macchina resta offline anche dopo riavvii 
   ripetuti.

Questo modello impedisce che credenziali admin compromesse riattivino una 
macchina ancora infetta. La chiave ha un sistema di recovery aziendale 
gestito da un key vault dedicato (dettagli in ROADMAP.md).

## Difesa suprema

NorthNarrow è la difesa suprema di ogni cosa esista su Windows e Linux.

NorthNarrow è il futuro. CrowdStrike è il passato.

---

## Regola d'oro

Questo file è il contratto. Ogni futura sessione di lavoro (con qualsiasi 
Claude o qualsiasi tool) parte leggendo questo file per primo. Se uno 
strumento contraddice questa visione, ha torto lo strumento.

La visione non si ridimensiona. Si costruisce a tappe in ordine fisso 
(vedi ROADMAP.md). Una tappa alla volta. Non si salta. Non si torna 
indietro. Mai.
