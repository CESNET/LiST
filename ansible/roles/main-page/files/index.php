<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>STaaS</title>
    <meta name="description" content="STaaS main site with links to the services">
    <style>
html {
  height: 100%;
}
body {
  position: relative;
  margin: 0;
  min-height: 100%;
}
h1 {
    font-family: verdana;
    font-size: 300%;
}
footer {
    display: block;
    position: absolute;
    right: 0;
    left: 0;
    bottom: 0;
    font-size: 10px;
    background-color: #DDDDDD;
    text-align: center;
    font-weight: bold;
    width: 100%;
}
header {
    display: block;
    position: relative;
    right: 0;
    left: 0;
    top: 0;
    background-color: #DDDDDD;
    text-align: center;
    font-weight: bold;
    width: 100%;
    padding-top: 1px;
    padding-bottom: 1px;
}
main {
    padding-top: 25px;
    margin: 0 auto;
    display: table;
}
.pane {
    float: left;
    border: 1px solid black;
    background-color: #CCCCCC;
    width: 200px;
    height: 200px;
    line-height: 200px;
    margin: 25px;
    text-align: center;
    font-width: bold;
    font-size: 30px;
    color: black;
    text-decoration: none;
}
.pane span {
    display: inline-block;
    line-height: 35px;
    vertical-align: middle;
}
    </style>
</head>
<body>

    <header>
        <h1>Security Tools as a Service</h1>
    </header>

    <main>
    <?php if (file_exists("liberouter-gui")) {?>
        <a href="/liberouter-gui/dist" class="pane"><span>Liberouter GUI</span></a>
    <?php } ?>

    <?php if (file_exists("Nemea-Dashboard")) {?>
        <a href="/Nemea-Dashboard" class="pane"><span>Nemea Dashboard</span></a>
    <?php } ?>

    <?php if (file_exists("scgui")) {?>
        <a href="/scgui" class="pane"><span>Security Cloud GUI</span></a>
    <?php } ?>

    <?php if (file_exists("nemea-status")) {?>
        <a href="/nemea-status" class="pane"><span>Nemea Status</span></a>
    <?php } ?>

    <?php if (file_exists("munin")) {?>
        <a href="/munin" class="pane">Munin</a>
    <?php } ?>

    <?php if (file_exists("/usr/share/nagios/html/")) {?>
        <a href="/nagios" class="pane">Nagios</a>
    <?php } ?>

    <?php if (file_exists("warden_receiver")) {?>
        <a href="/warden_receiver/incoming" class="pane"><span>Warden receiver</span></a>
    <?php } ?>
    </main>

    <footer>
        CESNET z. s. p. o. 2017
    </footer>

</body>
</html>
