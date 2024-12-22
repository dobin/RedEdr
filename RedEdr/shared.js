
// Function to display events in Tab 1
function displayEvents(events) {
    const eventContainer = document.getElementById('eventContainer');
    eventContainer.innerHTML = ''; // Clear previous content

    events.forEach(event => {
        const eventDiv = document.createElement('div');
        eventDiv.classList.add('event');

        let eventTitle = '';
        let eventHeader = '';
        let eventDetails = '';
        let eventLong = '';
        let eventCallstack = '';
        let detections = '';
        let etwti_startaddr = 0;
        for ([key, value] of Object.entries(event)) {
            if (typeof value === "number") {
                value = myHex(value);
            }

            // header
            if (key === 'time' || key === 'pid' || key === 'tid' ||
                key === 'krn_pid' || key === 'ppid' || key === 'observe' ||
                key === 'thread_id' || key === 'provider_name'  || key === 'id' || key == 'trace_id'
            ) {
                eventHeader += `<span class="highlight_a">${key}:${value}</span> `;
            } else if (key === 'type' || key === 'func' || key === 'event') {
                eventTitle += `<span class="highlight_b"><b>${value}</b></span> `;

            // detection
            } else if (key === 'detections') {
                detections = `<span class="highlight_e">detections:<br>${JSON.stringify(value, null, 0)}</span>`;

            // special for func == loaded_dll
            } else if (key == 'dlls') {
                eventDetails += JSON.stringify(value, null, 0);
                
            // callstack
            } else if (key == 'callstack' || key == 'stack_trace') {
                let x = '';
                for ([key_c, value_c] of Object.entries(value)) {
                    for ([key_d, value_d] of Object.entries(value_c)) {
                        if (typeof value_d === "number") {
                            value_d = myHex(value_d);
                        }
                        x += `${key_d}:${value_d} `;
                    }
                    x += "<br>";
                }

                //eventCallstack = '<span class="highlight_d">callstack:<br>' + JSON.stringify(value, null, 0) + "</span>";
                eventCallstack = '<span class="highlight_d">callstack:<br>' + x + "</span>";
            // important
            } else if (key === 'addr') {
                eventDetails += `<b>${key}:${value}</b> `;
            } else if (key === 'protect') {
                eventDetails += `<b>${key}:${value}</b> `;
            } else if (key === 'handle' && value != "FFFFFFFFFFFFFFFF") {
                eventDetails += `<b>${key}:${value}</b> `;

            // long
            } else if (key == 'name' || key == 'parent_name' ||
                key == 'image_path' || key == 'commandline' ||
                key == "working_dir") {
                eventLong += `<span class="highlight_c">${key}:${value}</span> <br>`;

            // rest
            } else {
               // ignore some ETWTI fields for now
               if (! key.startsWith("Calling") && 
                   ! key.startsWith("Target") && 
                   ! key.startsWith("Original"))
               {
                   // translate some ETWTI for now
                   if (key == 'ProtectionMask' || key == 'LastProtectionMask') {
                       value = translateProtectionFlags(value);
                   }
                   if (key == 'BaseAddress') {
                       etwti_startaddr = value;
                   }
                   if (key == 'RegionSize') {
                       value = value - etwti_startaddr;
                   }

                   eventDetails += `<span class="highlight_c">${key}:${value}</span> `;
               }
            }
        }

        eventDiv.innerHTML = eventTitle + eventHeader + "<br>"
            + eventDetails + (eventDetails.length != 0 ? "<br>" : "")
            + eventLong + eventCallstack
        if (detections.length != 0) {
            eventDiv.innerHTML += "<br>" + detections;
        }

        eventContainer.appendChild(eventDiv);
    });
}

// Function to display events in Tab 1
function displayDetections(detections) {
    const container = document.getElementById('detectionContainer');
    container.innerHTML = '';

    detections.forEach((detection, index) => {
        // Create a div for each detection
        const detectionDiv = document.createElement('div');
        detectionDiv.textContent = `${index}: ${detection}`;
        container.appendChild(detectionDiv);
    });
}

function translateProtectionFlags(flags) {
    // Define the mapping of protection flags to "rwx" permissions
    const protectionMapping = {
        0x01: "---", // PAGE_NOACCESS (no access, for completeness)
        0x02: "r--", // PAGE_READONLY
        0x04: "rw-", // PAGE_READWRITE
        0x08: "rw-c", // PAGE_WRITECOPY
        0x10: "--x", // PAGE_EXECUTE
        0x20: "r-x", // PAGE_EXECUTE_READ
        0x40: "rwx", // PAGE_EXECUTE_READWRITE
        0x80: "rwxc", // PAGE_EXECUTE_WRITECOPY
    };
    // Mask out modifiers that don't affect basic permissions
    const basicFlags = flags & 0xFF;
    // Get the permissions string from the mapping
    return protectionMapping[basicFlags] || "unknown";
}

function myHex(num) {
	if (num == 0x10000000000000000) {
		return "-1";
	}
	return "0x" + num.toString(16).toUpperCase();
}