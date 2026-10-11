# Performance validation

Syntetyczny FakeTransport, body 277 bajtow, 16 originow, C=32, Q=128. Streaming bez listy wszystkich wynikow. Python 3.14.2.

Tracemalloc byl wlaczony: wyniki sa pomiarem tego harnessu, bez SLA dla internetu. Czas pipeline obejmuje planner, scheduler, FakeTransport i detection; nie jest czystym czasem samego dispatchera.

| Sites | Registry build s | Registry build peak MiB | Pipeline s | Work peak MiB | Async tasks peak | HTTP peak | Queue peak | Detection us/result |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 100 | 0.048 | 0.79 | 0.045 | 0.272 | 34 | 32 | 100 | 59.88 |
| 1000 | 0.365 | 6.73 | 0.466 | 0.304 | 34 | 32 | 128 | 56.27 |
| 10000 | 4.283 | 62.55 | 6.721 | 0.373 | 34 | 32 | 128 | 78.20 |

## Interpretacja

- Liczba taskow nie rośnie z liczba definicji. 34 oznacza main+dispatcher+32 attempts w tym scenariuszu; timer oczekiwania moze utworzyc dodatkowy lekki task w scenariuszu cooldown.
- Work peak to nowe alokacje Python podczas search po utworzeniu registry, nie calkowity RSS. Registry i jego serializacja maja koszt O(S); peak budowania jest raportowany osobno.
- Queue nie przekroczyla 128, HTTP nie przekroczylo 32; kazda z definicji zwrocila wynik.
- Osobne testy sprawdzaja 100 rownoczesnych jobow, 30% odpowiedzi 429, wolny pierwszy request, wolnego odbiorce, slow cleanup, parser process timeout i lokalny TLS.
- Nie strojono limitow na podstawie nieistniejacych pomiarow publicznych platform. Brak danych o realnym RTT, skutecznosci markerow i przepustowosci proxy/SOCKS.

Ponowienie: `python benchmarks/run_synthetic.py`. Pelne metryki: `benchmarks/results.json`.
