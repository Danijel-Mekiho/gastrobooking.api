<em>@lang('main.MAIL.DEAR_CLIENT'),</em>

<p>@lang('main.MAIL.REGISTERING_BOOKING_SYSTEM')
    Gastro-Booking.com @lang('main.MAIL.IN_NAME') <?= $user->name ?>.
    @lang('main.MAIL.LOGIN_NAME'): <?= $user->email ?></p>

<p>@lang('main.MAIL.LOOKING_FORWARD_TO_COLLABORATE').</p>

<address>
    Gastro-Booking.com - @lang('main.MAIL.CZECH_REPUBLIC') <br>
    www.gastro-booking.com <br>
    @lang('main.MAIL.ONDAV LTD') <br>
    487, @lang('main.MAIL.ADDRESS') <br>
    @lang('main.MAIL.COMPANY_NUMBER_'): 09254062 <br>
</address>