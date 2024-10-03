# App Level Brain Dump

## PARCHAT as PC sandbox

The goal in my view for the PARCHAT is to pill people on the importance and power of PC. The best way to accomplish this in my view is to get people to empathize with the problems that PC solves, and to allow them to play with a (maybe real, maybe mocked) PC toolkit.

### App 0: Credentials (ZK)

Build custom credentials by securely applying computation over my private pods.

#### Possible forms
- Am I old enough
- Am I american
- Do I work at 0xPARC

### App 1: Locked messages (witness encryption)

The usecase here is like witness encrypt a message to some pod. For example I might want to send a message to a groupchat with thousands of people but only want those with a valid devcon ticket to be able to read my message. Alternatively there are more "fun" use cases like you gotta solve a sudoku or something to read my message.

#### Possible forms
- Timelocked message - Time capsule messages
- Ticket-gated message - buy your devcon ticket to see
- Puzzle gated message - solve a sudoku to unlock
- Voting gated message - message can only be unlocked if t/n participants agree
#### Tech requirements
- Executor needs to be pod-in-pod-out.
- Executor needs to have precompile functionality so we don't have to build up encryption from binary operations in the AST
- Need to decide if the production of the ct pod happens within an executor, whether that would be the same executor as the decryption

### App 2: Private stats (FHE)

The point of this app would be to compute stats across your private chats securely.

#### Possible forms
- Wordcloud
- Leaderboard of {who said "pods" the least, who's names being mentioned the most, etc}
- Compliance

#### Tech requirements
- Same as above

### App 3: Conditional information (MPC)

This is kinda similar to the WE usecases but should feel different. More of an emphasis should be placed on "discovering" new information via live participation rather than "unlocking" something.

#### Possible forms
- Private crush match - signal you like someone, and can get a response if and only if they signal back
- Can we date - ie via age / 2 + 7 within range
- Private enemy match - signal you dislike someone, find others who also dislike that person

#### Tech requirements
- Might need a separate communication channel depending on amount of data, lack of ordering requirements, etc

### App 3: Untamperable agents (IO)

This one we'd have to simulate but I think the angle here is to make cryptomata bots that you can configure somehow and unleash them onto the app.

#### Possible forms
- Negotiating agent - you give it a goal and it can go off and negotiate with someone on your behalf, without you being involved.
- Wingman - you make some bot to go and find you a partner
- Virus - a bot that doesn't stop bothering you until you share it with 5 other friends.

#### Tech requirements
- We'd likely simulate this one within a TEE
- Need some connection between <Partipant, Claims> which doesn't seem to be within the scope of an executor
