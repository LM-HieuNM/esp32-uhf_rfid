/**
 * Add gobals here
 */
var seconds 	= null;
var otaTimerVar =  null;
var wifiConnectInterval = null;

var isConnectedWifi = false;
/**
 * Initialize functions here.
 */
$(document).ready(function(){
	getUpdateStatus();
	// startDHTSensorInterval();
	getConnectInfo();
	$("#connect_wifi").on("click", function(){
		checkCredentials();
	}); 

    $("#disconnect_wifi").on("click", function(){
        disconnectWifi();
    }); 
    
    // Tab switching
    $(".tab-button").on("click", function(){
        // Remove active class from all buttons and panes
        $(".tab-button").removeClass("active");
        $(".tab-pane").removeClass("active");
        
        // Add active class to current button and corresponding pane
        $(this).addClass("active");
        $("#" + $(this).data("tab")).addClass("active");
    });

    // Login functionality
    const correctPassword = "1";

    function showError(message) {
        const errorElement = $("#login_error");
        errorElement.text(message);
        errorElement.addClass('shake');
        setTimeout(() => errorElement.removeClass('shake'), 500);
    }

    $("#login_button").on("click", function(){
        const enteredPassword = $("#login_password").val();
        if (enteredPassword === correctPassword) {
            $("#login-screen").hide();
            $("#main-content").show();
        } else {
            showError("Incorrect password. Please try again.");
        }
    });

    // Add Enter key support
    $("#login_password").on("keypress", function(e){
        if(e.which === 13) {
            $("#login_button").click();
        }
    });

    $("#apply_antenna").on("click", function(){
        saveAntennaConfig();
    });

    // Load current antenna configuration
    function loadAntennaConfig() {
        $.getJSON('/antennaConfig.json', function(data) {
            $("#power_level").val(data.power);
            data.antennas.forEach((enabled, index) => {
                document.getElementById(`ant${index + 1}`).checked = enabled;
            });
        });
    }

    // Load configuration when antenna tab is selected
    $(".tab-button[data-tab='antenna']").on("click", function(){
        loadAntennaConfig();
    });
});   

/**
 * Gets file name and size for display on the web page.
 */        
function getFileInfo() 
{
    var x = document.getElementById("selected_file");
    var file = x.files[0];

    document.getElementById("file_info").innerHTML = "<h4>File: " + file.name + "<br>" + "Size: " + file.size + " bytes</h4>";
}

/**
 * Handles the firmware update.
 */
function updateFirmware() 
{
    // Form Data
    var formData = new FormData();
    var fileSelect = document.getElementById("selected_file");
    
    if (fileSelect.files && fileSelect.files.length == 1) 
	{
        var file = fileSelect.files[0];
        formData.set("file", file, file.name);
        showToast(`Uploading ${file.name}, Firmware Update in Progress...`, 'info');

        // Http Request
        var request = new XMLHttpRequest();

        request.upload.addEventListener("progress", updateProgress);
        request.open('POST', "/OTAupdate");
        request.responseType = "blob";
        request.send(formData);
    } 
	else 
	{
        showToast('Select A File First', 'error');
    }
}

/**
 * Progress on transfers from the server to the client (downloads).
 */
function updateProgress(oEvent) 
{
    if (oEvent.lengthComputable) 
	{
        getUpdateStatus();
    } 
	else 
	{
        window.alert('total size is unknown')
    }
}

/**
 * Posts the firmware udpate status.
 */
function getUpdateStatus() 
{
    var xhr = new XMLHttpRequest();
    var requestURL = "/OTAstatus";
    xhr.open('POST', requestURL, false);
    xhr.send('ota_update_status');

    if (xhr.readyState == 4 && xhr.status == 200) 
	{		
        var response = JSON.parse(xhr.responseText);
						
	 	document.getElementById("latest_firmware").innerHTML = response.compile_date + " - " + response.compile_time

		// If flashing was complete it will return a 1, else -1
		// A return of 0 is just for information on the Latest Firmware request
        if (response.ota_update_status == 1) 
		{
    		// Set the countdown timer time
            seconds = 10;
            // Start the countdown timer
            otaRebootTimer();
        } 
        else if (response.ota_update_status == -1)
		{
            document.getElementById("ota_update_status").innerHTML = "!!! Upload Error !!!";
        }
    }
}

/**
 * Displays the reboot countdown.
 */
function otaRebootTimer() 
{	
    document.getElementById("ota_update_status").innerHTML = "OTA Firmware Update Complete. This page will close shortly, Rebooting in: " + seconds;

    if (--seconds == 0) 
	{
        clearTimeout(otaTimerVar);
        window.location.reload();
    } 
	else 
	{
        otaTimerVar = setTimeout(otaRebootTimer, 1000);
    }
}

/**
 * Gets DHT22 sensor temperature and humidity values for display on the web page.
 */
// function getDHTSensorValues()
// {
// 	$.getJSON('/dhtSensor.json', function(data) {
// 		$("#temperature_reading").text(data["temp"]);
// 		$("#humidity_reading").text(data["humidity"]);
// 	});
// }

/**
 * Sets the interval for getting the updated DHT22 sensor values.
 */
// function startDHTSensorInterval()
// {
// 	setInterval(getDHTSensorValues, 5000);    
// }

/**
 * Clears the connection status interval.
 */
function stopWifiConnectStatusInterval()
{
	if (wifiConnectInterval != null)
	{
		clearInterval(wifiConnectInterval);
		wifiConnectInterval = null;
	}
	// Remove connecting toast if it exists
	if (connectingToast) {
		connectingToast.classList.add('removing');
		connectingToast.addEventListener('animationend', () => {
			connectingToast.remove();
			connectingToast = null;
		});
	}
}

let connectingToast; // Variable to store the connecting toast
let disconnectingToast;

function getWifiConnectStatus() {
    var xhr = new XMLHttpRequest();
    var requestURL = "/wifiConnectStatus";
    xhr.open('POST', requestURL, false);
    xhr.send();
    
    if (xhr.readyState == 4 && xhr.status == 200) {
        var response = JSON.parse(xhr.responseText);
        
        if (response.wifi_connect_status == 2) {
            showToast('Failed to Connect. Please check your AP credentials and compatibility', 'error', 5000);
            stopWifiConnectStatusInterval();
        }
        else if (response.wifi_connect_status == 3) {
            showToast('Connection Success!', 'success');
            stopWifiConnectStatusInterval();
            getConnectInfo();
        }
    }
}

// Function to animate ellipsis
function animateEllipsis(toastElement) {
    let dots = 0;
    const maxDots = 3;
    const interval = setInterval(() => {
        if (dots < maxDots) {
            toastElement.textContent += '.';
            dots++;
        } else {
            toastElement.textContent = toastElement.textContent.replace(/\.+$/, '');
            dots = 0;
        }
    }, 500);

    // Clear interval when toast is removed
    toastElement.addEventListener('animationend', () => {
        clearInterval(interval);
    });
}

/**
 * Starts the interval for checking the connection status.
 */
function startWifiConnectStatusInterval()
{
	wifiConnectInterval = setInterval(getWifiConnectStatus, 2800);
}

/**
 * Connect WiFi function called using the SSID and password entered into the text fields.
 */
function connectWifi()
{
	// Get the SSID and password
	selectedSSID = $("#connect_ssid").val();
	pwd = $("#connect_pass").val();
	
	// Show connecting toast immediately
	if (!connectingToast) {
		connectingToast = document.createElement('div');
		connectingToast.className = 'toast info';
		connectingToast.textContent = 'Connecting';
		document.getElementById('toast-container').appendChild(connectingToast);
		animateEllipsis(connectingToast);
	}
	
	$.ajax({
		url: '/wifiConnect.json',
		dataType: 'json',
		method: 'POST',
		cache: false,
		headers: {'my-connect-ssid': selectedSSID, 'my-connect-pwd': pwd},
		data: {'timestamp': Date.now()}
	});
	
	startWifiConnectStatusInterval();
}


/**
 * Checks credentials on connect_wifi button click.
 */
function checkCredentials()
{
	credsOk = true;
	
	selectedSSID = $("#connect_ssid").val();
	pwd = $("#connect_pass").val();
	
	if (selectedSSID == "")
	{
		showToast('SSID cannot be empty!', 'error');
		credsOk = false;
	}
	if (pwd == "")
	{
		showToast('Password cannot be empty!', 'error');
		credsOk = false;
	}
	
	if (credsOk)
	{
		connectWifi();    
	}
}


/**
 * Shows the WiFi password if the box is checked.
 */
function showPassword()
{
	var x = document.getElementById("connect_pass");
	if (x.type === "password")
	{
		x.type = "text";
	}
	else
	{
		x.type = "password";
	}
}

/**
 * Gets the connection information for displaying on the web page.
 */
function getConnectInfo()
{
	$.getJSON('/wifiConnectInfo.json', function(data)
	{
		isConnectedWifi = true;
		$("#connected_ap_label").html("Connected to: ");
		$("#connected_ap").text(data["ap"]);
		
		$("#ip_address_label").html("IP Address: ");
		$("#wifi_connect_ip").text(data["ip"]);
		
		$("#netmask_label").html("Netmask: ");
		$("#wifi_connect_netmask").text(data["netmask"]);
		
		$("#gateway_label").html("Gateway: ");
		$("#wifi_connect_gw").text(data["gw"]);
		
		document.getElementById('disconnect_wifi').style.display = 'block';
	});
}

/**
 * Disconnects Wifi once the disconnect button is pressed and reloads the web page.
 */
function disconnectWifi()
{
	// Show disconnecting toast
	if (!disconnectingToast) {
		disconnectingToast = document.createElement('div');
		disconnectingToast.className = 'toast info';
		disconnectingToast.textContent = 'Disconnecting';
		document.getElementById('toast-container').appendChild(disconnectingToast);
		animateEllipsis(disconnectingToast);
	}

	$.ajax({
		url: '/wifiDisconnect.json',
		dataType: 'json',
		method: 'DELETE',
		cache: false,
		data: { 'timestamp': Date.now() }
	});

	// Remove disconnecting toast and reload after 2 seconds
	setTimeout(() => {
		if (disconnectingToast) {
			disconnectingToast.classList.add('removing');
			disconnectingToast.addEventListener('animationend', () => {
				disconnectingToast.remove();
				disconnectingToast = null;
				location.reload(true);
			});
		}
	}, 2000);
}

// Add this new function for showing toasts
function showToast(message, type = 'info', duration = 3000) {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    const container = document.getElementById('toast-container');
    container.appendChild(toast);

    // Remove toast after duration
    setTimeout(() => {
        toast.classList.add('removing');
        toast.addEventListener('animationend', () => {
            container.removeChild(toast);
        });
    }, duration);
}

function saveAntennaConfig() {
    const antennaConfig = {
        power: parseInt($("#power_level").val()),
        antennas: []
    };

    // Collect status of all antennas
    for (let i = 1; i <= 16; i++) {
        antennaConfig.antennas.push(document.getElementById(`ant${i}`).checked);
    }

    // Send configuration to server
    $.ajax({
        url: '/antennaConfig.json',
        dataType: 'json',
        method: 'POST',
        cache: false,
        contentType: 'application/json',
        data: JSON.stringify(antennaConfig),
        success: function(response) {
            showToast('Antenna configuration saved successfully!', 'success');
        },
        error: function() {
            showToast('Failed to save antenna configuration', 'error');
        }
    });
}

