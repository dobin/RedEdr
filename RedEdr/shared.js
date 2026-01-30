
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
        let etwti_startaddr = 0;
        for ([key, value] of Object.entries(event)) {
            if (typeof value === "number") {
                value = myHex(value);
            }

            // header
            if (key === 'etw_time' || key === 'etw_pid' || key === 'etw_process' || key === 'etw_tid' ||
                key === 'etw_pid' || key === 'etw_event_id' ||
                key === 'thread_id' || key === 'etw_provider_name'  || key === 'id' || key == 'trace_id'
            ) {
                eventHeader += `<span class="highlight_a">${key}:${value}</span> `;
            } else if (key === 'type' || key === 'func' || key === 'event' || key === 'task') {
                eventTitle += `<span class="highlight_b"><b>${value}</b></span> `;

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
                   eventDetails += `<span class="highlight_c">${key}:${value}</span> `;
               }
            }
        }

        eventDiv.innerHTML = eventTitle + eventHeader + "<br>"
            + eventDetails + (eventDetails.length != 0 ? "<br>" : "")
            + eventLong + eventCallstack

        eventContainer.appendChild(eventDiv);
    });
}

function myHex(num) {
	if (num == 0x10000000000000000) {
		return "-1";
	}
	return "0x" + num.toString(16).toUpperCase();
}