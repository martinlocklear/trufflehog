# TruffleHog Structural Overview

```mermaid
flowchart LR
    subgraph TruffleHog

        subgraph Source
            direction TB
            SourceDescription("`Sources are top level places we find data/files/text to _scan_`")
            subgraph ExampleSources
                GitSource["git Source <img src='https://git-scm.com/images/logo@2x.png' style='background-color:white'/>"]
                GitHubSource["GitHub Source <img src='https://github.githubassets.com/assets/GitHub-Mark-ea2971cee799.png' />"]
                FilesystemSource["File System Source <img src='https://cdn-icons-png.freepik.com/512/8602/8602255.png' />"]
                PostmanSource["Postman Source <img src='https://voyager.postman.com/logo/postman-logo-icon-orange.svg' />"]
            end
        end

        subgraph Unit
            direction TB
            UnitDescription("`Units are natural subdivisions of Sources, but still quite large`")
            FilesystemUnit[Directory]
            GitUnit[Git Repository]
            PostmanUnit[What is a Postman unit???]
        end

        subgraph Chunk
            direction TB
            ChunkDescription("`Chunks are the smallest units that we decompose our chunks into, and are subsequent passed on to detection`")
            FilesystemChunk[File Contents]
            GitRepositoryChunk["`git log diff hunks`"]
            PostmanChunk[What is a postman chunk???]
        end
        
        KeywordMatching["`**Keyword Matching**
_(Aho-Corsick)_

Match chunks to detectors based on the presence of specific keywords in the chunk`"]

        subgraph Detector
            direction RL
            subgraph DetectorDescription[" "]
                DetectorDescriptionText["`Detectors are the bits that actually check for the existence of a secret in a chunk, and (optionally) verify it`"]
                subgraph Detectors[Example Detectors]
                    direction TB
                    AwsDetector["AWS Detector <img src='https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRVj0jisdcvxnjyylo9HUKwS1p89RniwBu9Ew&s' style='background-color:white'/>"]
                    ZapierDetector["Zapier Detector <img src='https://cdn.iconscout.com/icon/free/png-256/free-zapier-logo-icon-download-in-svg-png-gif-file-formats--company-brand-world-logos-vol-4-pack-icons-282557.png' style='background-color:white'/>"]
                    TwilioDetector["Twilio Detector <img src='https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQG0S-NoPx0UwcGqbBbWTtMOcwftpFXQmphxA&s' style='background-color:white'/>"]
                end
            end    
            subgraph DetectorResponsibility[" "]
                direction LR
                
                CollectMatches["`**Collect Matches**

Detector specific regexes are run against the matched chunks, resulting in unverified secrets`"]
                VerifyMatches["`**Verify Matches**

Optionally, observed unverified secrets are verified by attempting to use them against live services`"]
                DedupMatches["`**Dedup Matches**

The same secret could be found in several places, so we dedup before verying against live services. There's also come caching that happens here`"]

                CollectMatches -- regex matched chunks --> DedupMatches
                DedupMatches -- deduped matches --> VerifyMatches
            end
        end

            subgraph Dispatcher
                direction TB
                NotifierDescription["`Results, verified or otherwise are sent to a dispatcher to be sent to whichever place we're updating about
                the results -- usually the command line.`"]
                ResultsDispatcher
            end

        SourceDescription -- decomposed into --> UnitDescription
        UnitDescription -- further decomposed into --> ChunkDescription
        ChunkDescription --> KeywordMatching
        KeywordMatching --> Detector
        Detector -- processed results --> ResultsDispatcher
        
        GitSource --> GitUnit
        GitHubSource --> GitUnit
        PostmanSource --> PostmanUnit
        FilesystemSource --> FilesystemUnit
        
        GitUnit --> GitRepositoryChunk
        PostmanUnit --> PostmanChunk
        FilesystemUnit --> FilesystemChunk
        
        GitRepositoryChunk --> KeywordMatching
        PostmanChunk --> KeywordMatching
        FilesystemChunk --> KeywordMatching
        
        style SourceDescription fill:#89553e
        style UnitDescription fill:#89553e
        style ChunkDescription fill:#89553e
        style KeywordMatching fill:#89553e
        style DetectorDescription fill:#89553e
        style DetectorDescriptionText fill:#89553e
        style NotifierDescription fill:#89553e
    end
```
