
set(srcs "main.c"
        "lib/wifi_app/wifi_app.c"
        "lib/https_server/keep_alive.c"
        "lib/https_server/http_server.c"
        "lib/app_nvs/app_nvs.c"
        "lib/tag_manager/TagManage.cpp"
        "lib/serial/serial.cpp"
        "lib/packet/packet.cpp"
        "lib/tag_manager/tag_list.cpp"
        "lib/board/button.c"
        "lib/time/sntp_time.c")

set(incs "lib/wifi_app"
        "lib/https_server"
        "lib/app_nvs"
        "lib/utils"
        "lib/tag_manager"
        "lib/serial"
        "lib/packet"
        "lib/board"
        "lib/time")

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${incs}"
                    EMBED_TXTFILES "certs/servercert.pem"
                                   "certs/prvtkey.pem"
                                   
                    EMBED_FILES    "webpage/favicon.ico"
                                   "webpage/app.css"
                                   "webpage/app.js"
                                   "webpage/index.html"
                                   "webpage/jquery-3.3.1.min.js")

