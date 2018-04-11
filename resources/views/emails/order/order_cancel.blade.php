<!DOCTYPE html>
<html>
<head>
    <meta http-equiv=Content-Type content="text/html; charset=windows-1250">
    <title>Your Gastro-Booking</title>
</head>
<body bgcolor="#FFFFFF" lang=CSlink=#000080 vlink=#800080 text="#000000">
<div>
    <TABLE width=600 BORDER=3 CELLPADDING=4 CELLSPACING=0>
        <COL width= 150px>
        <TR><TD>
                <IMG SRC="http://www.gastro-booking.com/assets/images/logomini.png">
            </TD><TD>
                <?php echo ($order->pick_up === 'Y') ? Lang::get("main.MAIL.PICK UP") : (($order->delivery_address && $order->delivery_phone) ? Lang::get("main.MAIL.DELIVERY") : Lang::get("main.MAIL.BOOKING FOR")); ?>
                &nbsp;&nbsp;&nbsp;<?= $order->cancellation  ?> &nbsp;&nbsp;&nbsp;@lang('main.MAIL.NUMBER'): <?= $order->order_number ?><BR>
                <?php echo ($order->delivery_address && $order->delivery_phone) ? $order->delivery_address . ",". Lang::get('main.MAIL.GPS_LATITUDE') ."- " . $order->delivery_latitude . ", ".Lang::get('main.MAIL.GPS: latitude')." - " . $order->delivery_longitude
                        : $restaurant->name; ?><BR>
            </TD></TR>
        <TR><TD>
                @lang('main.MAIL.CUSTOMER')
            </TD><TD>
                <?= $user->name ?> (@lang('main.MAIL.BOOKING_FROM') <?= $order->created_at->format('d.m.Y H:i') ?>)
                <?php echo ($order->delivery_address && $order->delivery_phone) ? ", ".Lang::get("main.MAIL.TEL").": ". $order->delivery_phone :
                           ($user->client->phone ? ", ".Lang::get("main.MAIL.TEL").": ". $user->client->phone : "" ); ?>
            </TD></TR>
        <TR><TD>
                @lang('main.MAIL.NUMBERS_PRICE')
            </TD><TD>
                <?= $order->persons?> @lang('main.MAIL.PERSONS') - <?= $orders_detail_count ?>  <?php if ($orders_detail_count == 1) { ?> @lang('main.MAIL.ITEMS1') <?php } else if ($orders_detail_count > 1 && $orders_detail_count < 5) { ?> @lang('main.MAIL.ITEMS2') <?php } else { ?> @lang('main.MAIL.ITEMS5') <?php } ?>- @lang('main.MAIL.TOTAL_') <?= ($orders_detail_total_price - (float)$order->gb_discount) ?> <?= $order->currency ?>
            </TD></TR>
        <TR><TD colspan=2>
                @lang('main.MAIL.NOTE'): <?= $order->comment ?>
            </TD></TR>
    </TABLE><BR>

    <FONT SIZE="+0"><B>@lang('main.MAIL.CANCELLED'):</B><BR></FONT>

    <TABLE width=600 BORDER=3 CELLPADDING=2 CELLSPACING=0>
        <COL width= 40px>
        <COL width= 0px>
        <COL width= 60px>
        <COL width= 0px>
        <COL width= 100px>
        <COL width= 100px style = "text-align: right">

        <?php foreach ($order->orders_detail as $orders_detail) {
            if ($orders_detail->status != 3 && !$orders_detail->side_dish) { ?>

        <TR><TD>
                <?= \DateTime::createFromFormat('Y-m-d H:i:s', $orders_detail->serve_at)->format('H:i') ?>
            </TD><TD style="text-align: center">
                <?= $orders_detail->x_number ?>@lang('main.MAIL.AVAILABLE SYMBOL')
            </TD><TD>
                <?= $orders_detail->menu_list->prefix ?>
            </TD><TD>
                <?php echo $orders_detail->is_child ? Lang::get("main.MAIL.CHILD_PORTION").': '  . $orders_detail->menu_list->name : $orders_detail->menu_list->name; ?>
            </TD><TD>
                <?= $orders_detail->client->user->name ?>
            </TD><TD>
                <?= $orders_detail->price ?>
                <?= $orders_detail->menu_list->currency ?> @lang('main.MAIL.AVAILABLE SYMBOL') <?= $orders_detail->x_number ?>
            </TD></TR>
        <?php if ($orders_detail->comment) { ?>
        <TR><TD colspan=6 >
                <?= $orders_detail->comment ?>
            </TD></TR>
        <?php } ?>

        <?php  if (count($orders_detail->sideDish)) {
        foreach ($orders_detail->sideDish as $sideDish) {
            if ($sideDish->status != 3) {
        ?>
        <TR><TD colspan="2" style="text-align: right">
                <?= $sideDish->x_number ?>@lang('main.MAIL.AVAILABLE SYMBOL')
            </TD><TD>
                <?= $sideDish->menu_list->prefix ?>
            </TD><TD>
                <?php echo $sideDish->is_child ? Lang::get("main.MAIL.CHILD_PORTION").': ' . $sideDish->menu_list->name : $sideDish->menu_list->name; ?>
            </TD><TD>
                <?= $sideDish->client->user->name ?>
            </TD><TD>
                <?= $sideDish->price ?>
                <?= $sideDish->menu_list->currency?> @lang('main.MAIL.AVAILABLE SYMBOL')<?= $sideDish->x_number ?>
            </TD></TR>
        <?php } } ?>
        <?php
        }
        } } ?>
        <TR><TD colspan=4 style="border-right: 0;">
                @lang('main.MAIL.TOTAL PRICE'): <?= $orders_detail_total_price ?> <?= $order->currency ?> - @lang('main.MAIL.DISCOUNT'): <?php echo ((float)$order->gb_discount > 0 ? (float)$order->gb_discount : 0) ?> <?= $order->currency ?>
            </TD><TD style = "text-align: right; border-left: 0;">
                @lang('main.MAIL.TOTAL')
            </TD><TD>
                <?= ($orders_detail_total_price - (float)$order->gb_discount) ?> <?= $order->currency ?>
            </TD></TR>
    </TABLE>

    <TABLE style = "text-decoration: line-through" width=600 BORDER=3 CELLPADDING=2 CELLSPACING=0>
        <COL width= 40px>
        <COL width= 0px>
        <COL width= 60px>
        <COL width= 0px>
        <COL width= 100px>
        <COL width= 100px style = "text-align: right">
        <?php foreach ($order->orders_detail as $orders_detail) {
        if ( $orders_detail->status == 3  && (($orders_detail->side_dish && $orders_detail->mainDish->status != 3) || (!$orders_detail->side_dish))){
        ?>
        <TR><TD>
                <?= \DateTime::createFromFormat('Y-m-d H:i:s', $orders_detail->serve_at)->format('H:i') ?>
            </TD><TD style="text-align: center">
                <?=  $orders_detail->x_number ?>@lang('main.MAIL.AVAILABLE SYMBOL')
            </TD><TD>
                <?= $orders_detail->menu_list->prefix ?>
            </TD><TD>
                <?php echo $orders_detail->is_child ? Lang::get("main.MAIL.CHILD_PORTION").': ' . $orders_detail->menu_list->name : $orders_detail->menu_list->name; ?>
            </TD><TD>
                <?= $orders_detail->client->user->name ?>
            </TD><TD>
                <?= $orders_detail->price ?>
                <?= $orders_detail->menu_list->currency ?> @lang('main.MAIL.AVAILABLE SYMBOL') <?= $orders_detail->x_number ?>
            </TD></TR>
        <?php if ($orders_detail->comment) { ?>
        <TR><TD colspan=6 >
                <?= $orders_detail->comment ?>
            </TD></TR>
        <?php } ?>

        <?php  if (count($orders_detail->sideDish)) {
        foreach ($orders_detail->sideDish as $sideDish) {

        ?>
        <TR><TD colspan="2" style="text-align: right">
                <?= $sideDish->x_number ?>@lang('main.MAIL.AVAILABLE SYMBOL')
            </TD><TD>
                <?= $sideDish->menu_list->prefix ?>
            </TD><TD>
                <?php echo $sideDish->is_child ? Lang::get("main.MAIL.CHILD_PORTION").': ' . $sideDish->menu_list->name : $sideDish->menu_list->name; ?>
            </TD><TD>
                <?= $sideDish->client->user->name ?>
            </TD><TD>
                <?= $sideDish->price ?>
                <?= $sideDish->menu_list->currency?> @lang('main.MAIL.AVAILABLE SYMBOL') <?= $sideDish->x_number ?>
            </TD></TR>
        <?php } } ?>
        <?php
        }
        }?>
        <TR>
    </TABLE>
    <BR>
    @lang('main.MAIL.ENJOY_YOUR_MEAL')!<BR>

    <a HREF="http://www.gastro-booking.com/">www.gastro-booking.com</a>
</div>
</body></html>
