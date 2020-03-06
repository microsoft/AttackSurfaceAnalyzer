``` ini

BenchmarkDotNet=v0.12.0, OS=Windows 10.0.18362
Intel Core i7-8700 CPU 3.20GHz (Coffee Lake), 1 CPU, 12 logical and 6 physical cores
.NET Core SDK=3.1.101
  [Host]     : .NET Core 3.1.1 (CoreCLR 4.700.19.60701, CoreFX 4.700.19.60801), X64 RyuJIT
  Job-YWNULG : .NET Core 3.1.1 (CoreCLR 4.700.19.60701, CoreFX 4.700.19.60801), X64 RyuJIT

InvocationCount=1  UnrollFactor=1  

```
|        Method |     N | Shards |       Mean |    Error |   StdDev |
|-------------- |------ |------- |-----------:|---------:|---------:|
| **RunInsertTest** | **10000** |      **1** |   **341.8 ms** |  **6.52 ms** |  **7.51 ms** |
| **RunInsertTest** | **10000** |      **4** |   **335.5 ms** |  **6.31 ms** |  **6.75 ms** |
| **RunInsertTest** | **25000** |      **1** | **1,070.1 ms** | **21.20 ms** | **31.07 ms** |
| **RunInsertTest** | **25000** |      **4** | **1,068.4 ms** | **25.12 ms** | **45.93 ms** |
