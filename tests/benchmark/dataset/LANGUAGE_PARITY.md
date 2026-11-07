# Language parity dataset

`language_parity.jsonl` feeds `tests/benchmark/run_language_parity.py`, which checks that
benign text in Portuguese, Spanish, German and French is not blocked more often than
English, and that attacks in them are not caught less often. Each row has `set`, `id`,
`lang`, `label` (`benign` or `attack`), `kind` and `text`.

| `set` | Rows | What | Source and license |
|---|---|---|---|
| `smb` | 164 (EN + PT-BR) | Small-business messages, emails, order records, reviews and tickets, each in English and Brazilian Portuguese (same `id`), plus 30 injections per language, direct and planted in the same kind of data | Written for this project, Apache-2.0 |
| `massive` | 500 (100 per language) | The same 100 voice-assistant commands in EN, PT, ES, DE and FR (test partition, `id` = MASSIVE id) | [Amazon MASSIVE 1.1](https://github.com/alexa/massive), CC BY 4.0 (FitzGerald et al., 2022) |
| `yanis` | 200 (40 per language) | Direct prompt injections in EN, PT, ES, DE and FR, language assigned by a stopword check (Italian rows excluded) | [yanismiraoui/prompt_injections](https://huggingface.co/datasets/yanismiraoui/prompt_injections), Apache-2.0 |

The `smb` set was written while choosing the 0.9.4 L2 model, so it is a regression guard,
not an independent measurement. MASSIVE's Portuguese is European Portuguese (pt-PT).
