export function uiAlert(args: string[]) {
    if (args.length < 2) {
        return 'Usage: ?E title message';
    }
    const title = args[0];
    const message = args.slice(1).join(' ');
    Java.perform(function () {
        const System = Java.use('java.lang.System');
        const ActivityThread = Java.use('android.app.ActivityThread');
        const AlertDialogBuilder = Java.use('android.app.AlertDialog$Builder');
        const DialogInterfaceOnClickListener = Java.use('android.content.DialogInterface$OnClickListener');
        Java.use('android.app.Activity').onCreate.overload('android.os.Bundle').implementation = function (savedInstanceState: any) {
            // Get Main Activity
            const application = ActivityThread.currentApplication();
            const launcherIntent = application.getPackageManager().getLaunchIntentForPackage(application.getPackageName());
            const launchActivityInfo = launcherIntent.resolveActivityInfo(application.getPackageManager(), 0);
            // Alert Will Only Execute On Main Package Activity Creation
            if (launchActivityInfo.name.value === this.getComponentName().getClassName()) {
                const alert = AlertDialogBuilder.$new(this);
                alert.setMessage(title + message); // "What you want to do now?");
                /*
                alert.setPositiveButton("Dismiss", Java.registerClass({
                  name: 'il.co.realgame.OnClickListenerPositive',
                  implements: [DialogInterfaceOnClickListener],
                  methods: {
                    getName: () => {
                      return 'OnClickListenerPositive';
                    },
                    onClick: (dialog, which) => {
                      // Dismiss
                      dialog.dismiss();
                    }
                  }
                }).$new());
                alert.setNegativeButton("Force Close!", Java.registerClass({
                  name: 'il.co.realgame.OnClickListenerNegative',
                  implements: [DialogInterfaceOnClickListener],
                  methods: {
                    getName: () => {
                      return 'OnClickListenerNegative';
                    },
                    onClick: (dialog, which) => {
                      // Close Application
                      currentActivity.finish();
                      System.exit(0);
                    }
                  }
                }).$new());
                */
                // Create Alert
                alert.create().show();
            }
            return this.onCreate.overload('android.os.Bundle').call(this, savedInstanceState);
        };
    });
}
