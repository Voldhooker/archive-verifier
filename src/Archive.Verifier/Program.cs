using Archive.Verifier;

return args switch
{
    ["export", .. string[] rest] => await ExportCommand.RunAsync(rest, Console.Out, Console.Error),
    ["set", .. string[] rest] => SetCommand.Run(rest, Console.Out, Console.Error),
    ["verify", .. string[] rest] => VerifyCommand.Run(rest, Console.Out, Console.Error),
    _ => VerifyCommand.Run(args, Console.Out, Console.Error)
};
