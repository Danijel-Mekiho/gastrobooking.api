<!DOCTYPE html>
<html>
<head>
    <meta http-equiv=Content-Type content="text/html; charset=windows-1250">
    <title>Your Gastro-Booking</title>
</head>
<body bgcolor="#FFFFFF" lang=CSlink=#000080 vlink=#800080 text="#000000">
<div>
    <TABLE width=900 BORDER=3 CELLPADDING=4 CELLSPACING=0>
        <COL width= 150px>
        <TR><TD>
                <IMG SRC="http://www.gastro-booking.com/assets/images/logomini.png">
            </TD><TD>
                @lang('main.MAIL.REQUEST_FOR')
                <?php echo (isset($order->request_order_detail[0]) && isset($order->request_order_detail[0]->serve_at)) ? date("d.m.Y h:m", strtotime($order->request_order_detail[0]->serve_at)) : ''  ?>
                &nbsp;&nbsp;&nbsp;@lang('main.MAIL.TOTAL'): <?php echo $order->ID; ?>
                <BR>
                <?php if($restaurant){ ?>
                    <?php echo $restaurant->name; ?>, 
                    <?php echo $restaurant->street; ?>, 
                    <?php echo $restaurant->city; ?>, 
                    <?php echo $restaurant->www; ?>,
                    @lang('main.MAIL.TEL'): <?php echo $restaurant->phone; ?>,
                    @lang('main.MAIL.MOB').: <?php echo $restaurant->SMS_phone; ?>
                <?php } else { ?>
                    <?php echo $new_restaurant['name']; ?>, 
                    <?php echo $new_restaurant['address']; ?>, 
                <?php } ?>
                <BR>
            </TD></TR>
        <TR><TD>
                @lang('main.MAIL.CUSTOMER')
            </TD><TD>
                <?= $user->name ?> (@lang('main.MAIL.BOOKING_FROM') <?= $order->created_at->format('d.m.Y H:i') ?>)
                <?php echo ($order->delivery_address && $order->delivery_phone) ? ", ".Lang::get("main.MAIL.TEL").": ". $order->delivery_phone :
                           ($user->client->phone ? ", ".Lang::get("main.MAIL.TEL").": ". $user->client->phone : "" ); ?>
            </TD></TR>
        <TR><TD>
                @lang('main.MAIL.NUMBERS_AND_PRICE')
            </TD><TD>
                <?= $order->persons?> @lang('main.MAIL.PERSONS') - <?= $orders_detail_count ?> @lang('main.MAIL.ITEMS') - @lang('main.MAIL.TOTAL_')
                <?php
                if ($orders_detail_total_price && $orders_detail_total_price != '0.00' && $orders_detail_total_price > 0) {
                   echo $orders_detail_total_price .''.$order->currency;
                }
                ?>
            </TD></TR>
        <TR><TD colspan=2>
                @lang('main.MAIL.NOTE'): <?= $order->comment ?>
            </TD></TR>
    </TABLE><BR>

    <?php if($checkConfirm == 1){ ?>
    <TABLE width=900 BORDER=3 CELLPADDING=2 CELLSPACING=0>
        <COL width= 40px>
        <COL width= 0px>
        <COL width= 200px>
        <COL width= 400px>
        <COL width= 100px>
        <COL width= 100px style = "text-align: right">

        <?php foreach ($orders_detail_filtered as $key => $orders_detail) {
        if ($orders_detail->status != 3) { ?>

        <TR>
            <TD>
                <?php
                if (!$orders_detail->side_dish) {
                    echo \DateTime::createFromFormat('Y-m-d H:i:s', $orders_detail->serve_at)->format('H:i');
                }
                ?>
            </TD>
            <TD style="text-align: center">
                <?= $orders_detail->x_number ?>x
            </TD>
            <TD>
                <?php echo $orders_detail['requestMenu']->confirmed_name; ?>
            </TD>
            <TD>
                <?php echo $user->name; ?>
            </TD>
            <TD>
                <?php
                if ($orders_detail->price && $orders_detail->price != '0.00' && $orders_detail->price > 0) {
                   echo $orders_detail->price .''.$order->currency.' '.Lang::get("main.MAIL.AVAILABLE SYMBOL").' '.$orders_detail->x_number;
                }
                ?>
            </TD>
        </TR>
        <?php if ($orders_detail->comment) { ?>
        <TR><TD colspan=5 >
                <?= $orders_detail->comment ?>
            </TD></TR>
        <?php } 

        } } ?>
        <TR><TD colspan=4 style = "text-align: right">
                @lang('main.MAIL.TOTAL')
            </TD><TD>
                <?php
                if ($orders_detail_total_price && $orders_detail_total_price != '0.00' && $orders_detail_total_price > 0) {
                   echo $orders_detail_total_price .''.$order->currency;
                }
                ?>
            </TD></TR>
    </TABLE><BR>
    <?php } ?>

    <?php if($checkcancel == 1){ ?>
    <FONT SIZE="+0"><B>@lang('main.MAIL.CANCELLED'):</B><BR></FONT>
    <BR>
    <TABLE style = "text-decoration: line-through" width=900 BORDER=3 CELLPADDING=2 CELLSPACING=0>
        <COL width= 40px>
        <COL width= 0px>
        <COL width= 200px>
        <COL width= 400px>
        <COL width= 100px>
        <COL width= 100px style = "text-align: right">
        <?php foreach ($orders_detail_filtered as $key => $orders_detail) {
        if ( $orders_detail->status == 3  ){
        ?>
        <TR>
            <TD>
                <?php
                if (!$orders_detail->side_dish) {
                    echo \DateTime::createFromFormat('Y-m-d H:i:s', $orders_detail->serve_at)->format('H:i');
                }
                ?>
            </TD>
            <TD style="text-align: center">
                <?=  $orders_detail->x_number ?>@lang('main.MAIL.AVAILABLE SYMBOL')
            </TD>
            <TD>
                <?php echo $orders_detail['requestMenu']->confirmed_name; ?>
            </TD>
            <TD>
                <?php echo $user->name; ?>
            </TD>
            <TD>
                <?php
                if ($orders_detail->price && $orders_detail->price != '0.00' && $orders_detail->price > 0) {
                   echo $orders_detail->price .''.$order->currency.' '.Lang::get("main.MAIL.AVAILABLE SYMBOL").' '.$orders_detail->x_number;
                }
                ?>
            </TD>
        </TR>
        <?php if ($orders_detail->comment) { ?>
        <TR><TD colspan=5 >
                <?= $orders_detail->comment ?>
            </TD></TR>
        <?php } 

        }
        }?>
        <TR>
    </TABLE>
    <BR>
    <?php } ?>
    @lang('main.MAIL.ENJOY_YOUR_MEAL')!<BR>

    <A HREF="http://www.gastro-booking.com/">www.gastro-booking.com</A>
</div>
</body></html>
