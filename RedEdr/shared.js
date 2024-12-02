
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
        for (const [key, value] of Object.entries(event)) {
            // header
            if (key === 'type' || key === 'time' || key === 'pid' || key === 'tid' ||
                key === 'krn_pid' || key === 'ppid' || key === 'observe') {
                eventHeader += `<span class="highlight_a">${key}:${value}</span> `;
            } else if (key === 'func' || key === 'callback') {
                eventTitle += `<span class="highlight_b"><b>${value}</b></span> `;

                // detection
            } else if (key === 'detections') {
                detections = `<span class="highlight_e">detections:<br>${JSON.stringify(value, null, 0)}</span>`;

                // callstack
            } else if (key == 'callstack') {
                eventCallstack = '<span class="highlight_d">callstack:<br>' + JSON.stringify(value, null, 0) + "</span>";

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
                eventDetails += `<span class="highlight_c">${key}:${value}</span> `;
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