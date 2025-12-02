# Webserver for my personal site

why use something fancy like apache or nginx to serve my static files? Thats for losers!!

Nothing says #developer like serving your CV on a webserver you wrote from scratch.

Currently it is single threaded, managed by a bunch of poll calls to each socket currently open. This removes a lot of the socket creation/deletion overhead, but of course also constrains you to the speed of your machines CPU without taking advantage of all of its cores. Don't use this if your server has more than 1 core/thread, or do, I'm just a readme.

here is the call graph:
![callgraph for pws](resources/callgraph.png "callgraph")